//! Linux kernel-log (`syslog` / `dmesg`) USB device reader.
//!
//! The kernel logs each USB enumeration as a short block keyed by a bus id, e.g.
//! ```text
//! Mar 24 15:47:28 kernel: [ 2.350118] usb 2-1: New USB device found, idVendor=80ee, idProduct=0021, bcdDevice= 1.00
//! Mar 24 15:47:28 kernel: [ 2.350143] usb 2-1: Product: USB Tablet
//! Mar 24 15:47:28 kernel: [ 2.350146] usb 2-1: Manufacturer: VirtualBox
//! Mar 24 15:47:28 kernel: [ 2.350150] usb 2-1: SerialNumber: 0123ABCD
//! ```
//! This reader stitches the block back into a [`DeviceConnection`] (bus, VID/PID, serial,
//! friendly name, first-seen time). The syslog timestamp is **year-less** (a BSD-format
//! forensic limitation) and **host-local**, so the caller supplies the reference `year`
//! and the epoch is a naive-local conversion — the same caveat the setupapi reader carries.

use crate::setupapi::civil_to_epoch;
use crate::{Bus, DeviceConnection, Provenance, Stamp};

/// Parse Linux kernel USB-enumeration blocks from `syslog` / `dmesg` text.
///
/// `year` is the reference year for the year-less BSD timestamps; `file` is recorded in
/// each record's [`Provenance`].
#[must_use]
pub fn parse_linux_syslog(text: &str, file: &str, year: i64) -> Vec<DeviceConnection> {
    let mut out = Vec::new();
    let mut current: Option<Partial> = None;
    for (idx, line) in text.lines().enumerate() {
        if let Some(started) = Partial::start(line, year, idx + 1) {
            if let Some(prev) = current.take() {
                out.push(prev.finish(file));
            }
            current = Some(started);
        } else if let Some(dev) = current.as_mut() {
            dev.absorb(line);
        }
    }
    if let Some(dev) = current.take() {
        out.push(dev.finish(file));
    }
    out
}

/// A device block being assembled from consecutive same-`busid` lines.
struct Partial {
    busid: String,
    vid: Option<u16>,
    pid: Option<u16>,
    epoch: Option<i64>,
    line: usize,
    product: Option<String>,
    serial: Option<String>,
}

impl Partial {
    /// Begin a block from a `New USB device found` line, or `None` for any other line.
    fn start(line: &str, year: i64, line_no: usize) -> Option<Self> {
        let (busid, msg) = usb_message(line)?;
        let rest = msg.strip_prefix("New USB device found,")?;
        Some(Self {
            busid: busid.to_string(),
            vid: hex_field(rest, "idVendor="),
            pid: hex_field(rest, "idProduct="),
            epoch: bsd_epoch(line, year),
            line: line_no,
            product: None,
            serial: None,
        })
    }

    /// Fold a `Product:` / `SerialNumber:` follow-up line for the same bus id.
    fn absorb(&mut self, line: &str) {
        let Some((busid, msg)) = usb_message(line) else {
            return;
        };
        if busid != self.busid {
            return;
        }
        if let Some(product) = msg.strip_prefix("Product: ") {
            self.product = Some(product.trim().to_string());
        } else if let Some(serial) = msg.strip_prefix("SerialNumber: ") {
            self.serial = Some(serial.trim().to_string());
        }
    }

    fn finish(self, file: &str) -> DeviceConnection {
        DeviceConnection {
            bus: Bus::Usb,
            device_class_guid: None,
            vid: self.vid,
            pid: self.pid,
            device_serial: self.serial,
            serial_is_os_generated: false,
            friendly_name: self.product,
            device_instance_id: format!("usb/{}", self.busid),
            first_install: self.epoch.map(Stamp::authoritative),
            last_install: None,
            last_arrival: None,
            last_removal: None,
            parent_id_prefix: None,
            volume_guid: None,
            drive_letter: None,
            volume_serial: None,
            disk_signature: None,
            dma_capable: Bus::Usb.is_dma_capable(),
            mitre: Vec::new(),
            source: Provenance {
                file: file.to_string(),
                line: self.line,
            },
        }
    }
}

/// Split the `usb <busid>: <message>` portion out of a kernel-log line.
fn usb_message(line: &str) -> Option<(&str, &str)> {
    let after = line.find("usb ").map(|i| &line[i + 4..])?;
    after.split_once(": ")
}

/// Read a `<tag><4-hex>` field (e.g. `idVendor=80ee`) as a `u16`.
fn hex_field(text: &str, tag: &str) -> Option<u16> {
    let start = text.find(tag)? + tag.len();
    let hex = text.get(start..start + 4)?;
    u16::from_str_radix(hex, 16).ok()
}

/// Parse the leading BSD syslog timestamp (`MMM DD HH:MM:SS`, host-local) to epoch
/// seconds using the supplied `year`.
fn bsd_epoch(line: &str, year: i64) -> Option<i64> {
    let mut tok = line.split_whitespace();
    let month = month_number(tok.next()?)?;
    let day: i64 = tok.next()?.parse().ok()?;
    let mut hms = tok.next()?.split(':');
    let hour: i64 = hms.next()?.parse().ok()?;
    let min: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next()?.parse().ok()?;
    civil_to_epoch(year, month, day, hour, min, sec)
}

/// Three-letter English month abbreviation → 1-12, or `None`.
fn month_number(name: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    MONTHS
        .iter()
        .position(|&m| m == name)
        .map(|i| i64::try_from(i).unwrap_or(0) + 1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const BLOCK: &str = "\
Mar 24 15:47:28 kernel: [    1.501698] usb 2-1: new full-speed USB device number 2 using ohci-pci
Mar 24 15:47:28 kernel: [    2.350118] usb 2-1: New USB device found, idVendor=0781, idProduct=5583, bcdDevice= 1.00
Mar 24 15:47:28 kernel: [    2.350126] usb 2-1: New USB device strings: Mfr=1, Product=3, SerialNumber=2
Mar 24 15:47:28 kernel: [    2.350143] usb 2-1: Product: Ultra Fit
Mar 24 15:47:28 kernel: [    2.350146] usb 2-1: Manufacturer: SanDisk
Mar 24 15:47:28 kernel: [    2.350150] usb 2-1: SerialNumber: 0123ABCD4567
Mar 24 15:47:29 kernel: [    2.400000] some unrelated line without a device";

    #[test]
    fn parses_a_usb_block_into_a_connection() {
        let conns = parse_linux_syslog(BLOCK, "syslog", 2026);
        assert_eq!(conns.len(), 1);
        let c = &conns[0];
        assert_eq!(c.bus, Bus::Usb);
        assert_eq!(c.vid, Some(0x0781));
        assert_eq!(c.pid, Some(0x5583));
        assert_eq!(c.device_serial.as_deref(), Some("0123ABCD4567"));
        assert_eq!(c.friendly_name.as_deref(), Some("Ultra Fit"));
        assert_eq!(c.device_instance_id, "usb/2-1");
        // Mar 24 15:47:28 with year 2026 (naive-local → epoch).
        assert_eq!(
            c.first_install.as_ref().map(|s| s.value),
            civil_to_epoch(2026, 3, 24, 15, 47, 28)
        );
        assert_eq!(c.source.line, 2);
    }

    #[test]
    fn two_devices_and_a_serialless_device() {
        let text = "\
Jan  2 00:00:00 kernel: usb 1-1: New USB device found, idVendor=abcd, idProduct=0001
Jan  2 00:00:00 kernel: usb 1-1: Product: Tablet
Feb 15 12:00:00 kernel: usb 3-2: New USB device found, idVendor=1234, idProduct=5678
Feb 15 12:00:00 kernel: usb 9-9: Product: WrongBus
Feb 15 12:00:00 kernel: usb 3-2: SerialNumber: SN9";
        let conns = parse_linux_syslog(text, "dmesg", 2026);
        assert_eq!(conns.len(), 2);
        // first device: single-digit day (space-padded), no serial line
        assert_eq!(conns[0].device_serial, None);
        assert_eq!(conns[0].friendly_name.as_deref(), Some("Tablet"));
        // second device: a mismatched-bus follow-up is ignored, the right one absorbed
        assert_eq!(conns[1].device_serial.as_deref(), Some("SN9"));
        assert_eq!(conns[1].friendly_name, None);
    }

    #[test]
    fn malformed_lines_and_bad_month_never_panic() {
        assert!(parse_linux_syslog("", "f", 2026).is_empty());
        assert!(parse_linux_syslog("not a kernel line at all\n\0\0", "f", 2026).is_empty());
        assert_eq!(month_number("Zzz"), None);
        // a New-device line with an unparseable timestamp still yields a record (no epoch)
        let c = &parse_linux_syslog(
            "Zzz 99 99:99:99 kernel: usb 2-1: New USB device found, idVendor=0781, idProduct=5583",
            "f",
            2026,
        )[0];
        assert_eq!(c.first_install, None);
        assert_eq!(c.vid, Some(0x0781));
    }
}
