//! USB ID resolution — `VID`/`PID` → vendor / product **name**.
//!
//! A **non-authoritative enrichment** over [`DeviceConnection`](crate::DeviceConnection):
//! the raw numeric `vid`/`pid` parsed from evidence stay the authoritative values;
//! a resolved name is only a lookup convenience for the analyst.
//!
//! Two sources, no third-party data vendored into the crate:
//! - [`UsbIdDb::common`] — a small **hand-authored** table of common,
//!   forensically-relevant USB vendors (individual `VID → name` *facts*, which are
//!   not copyrightable). Zero-config; resolves the devices seen most in casework.
//! - [`UsbIdDb::parse`] — parses the full linux-usb.org `usb.ids` text format when
//!   the operator supplies it at runtime. `usb.ids` (© Stephen J. Gowdy, dual
//!   GPL-2.0 / BSD-3-Clause) is **not** bundled — load it from a path/env at run time.

use std::collections::BTreeMap;

/// A USB-ID lookup table: `VID → vendor name` and `(VID, PID) → product name`.
#[derive(Debug, Default, Clone)]
pub struct UsbIdDb {
    vendors: BTreeMap<u16, String>,
    products: BTreeMap<(u16, u16), String>,
}

impl UsbIdDb {
    /// Parse the linux-usb.org `usb.ids` text format (operator-supplied at runtime).
    ///
    /// Lenient and panic-free: comment (`#`) and blank lines are skipped, a vendor
    /// is `VVVV␠␠Name` at column 0, a product is `␉PPPP␠␠Name` (one tab), interface
    /// lines (two tabs) and non-vendor sections (`C`, `AT`, `HID`, `VT`, …) are
    /// skipped, and a product only attaches to the vendor currently in scope.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut db = Self::default();
        let mut current_vendor: Option<u16> = None;
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix('\t') {
                // one leading tab = product; two = interface line (skip).
                if rest.starts_with('\t') {
                    continue;
                }
                if let (Some(vid), Some((pid, name))) = (current_vendor, parse_id_line(rest)) {
                    db.products.insert((vid, pid), name.to_owned());
                }
                continue;
            }
            // Column-0 line: a vendor (4 hex + two spaces) or a section header.
            if let Some((vid, name)) = parse_id_line(line) {
                db.vendors.insert(vid, name.to_owned());
                current_vendor = Some(vid);
            } else {
                current_vendor = None; // section header ends the vendor's scope.
            }
        }
        db
    }

    /// The built-in, hand-authored table of common forensic-relevant USB vendors.
    ///
    /// Individual `VID → name` facts (not the copyrightable `usb.ids` compilation);
    /// zero-config coverage of the storage/controller vendors seen most in casework.
    /// For full coverage, load `usb.ids` at runtime via [`parse`](Self::parse).
    #[must_use]
    pub fn common() -> Self {
        const COMMON: &[(u16, &str)] = &[
            (0x0781, "SanDisk Corp."),
            (0x0951, "Kingston Technology"),
            (
                0x090c,
                "Silicon Motion, Inc. - Taiwan (formerly Feiya Technology Corp.)",
            ),
            (0x04e8, "Samsung Electronics Co., Ltd"),
            (0x0930, "Toshiba Corp."),
            (0x13fe, "Phison Electronics Corp."),
            (0x154b, "PNY"),
            (0x18a5, "Verbatim, Ltd"),
            (0x8564, "Transcend Information, Inc."),
            (0x058f, "Alcor Micro Corp."),
            (0x1b1c, "Corsair"),
            (0x0483, "STMicroelectronics"),
            (0x1f75, "Innostor Technology Corporation"),
            (0x1516, "CompUSA"),
            (0x048d, "Integrated Technology Express, Inc."),
            (0x174c, "ASMedia Technology Inc."),
            (
                0x152d,
                "JMicron Technology Corp. / JMicron USA Technology Corp.",
            ),
            (0x14cd, "Super Top"),
            (0x0bda, "Realtek Semiconductor Corp."),
            (0x05dc, "Lexar Media, Inc."),
            (0x0409, "NEC Corp."),
            (0x1058, "Western Digital Technologies, Inc."),
            (0x059f, "LaCie, Ltd"),
            (0x04b4, "Cypress Semiconductor Corp."),
            (0x067b, "Prolific Technology, Inc."),
        ];
        let mut db = Self::default();
        for &(vid, name) in COMMON {
            db.vendors.insert(vid, name.to_owned());
        }
        db
    }

    /// Resolve a vendor id to its name, if known.
    #[must_use]
    pub fn vendor_name(&self, vid: u16) -> Option<&str> {
        self.vendors.get(&vid).map(String::as_str)
    }

    /// Resolve a (vendor, product) pair to the product name, if known.
    #[must_use]
    pub fn product_name(&self, vid: u16, pid: u16) -> Option<&str> {
        self.products.get(&(vid, pid)).map(String::as_str)
    }

    /// Number of vendors in the table.
    #[must_use]
    pub fn vendor_count(&self) -> usize {
        self.vendors.len()
    }

    /// `true` when no vendors are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vendors.is_empty()
    }
}

/// Parse a `VVVV␠␠Name` id line into `(id, name)`. Panic-free (no slice indexing);
/// returns `None` unless the first four chars are hex followed by exactly two spaces
/// and a non-empty name — which cleanly rejects section headers (`C 00`, `VT 0100`).
fn parse_id_line(s: &str) -> Option<(u16, &str)> {
    let id = u16::from_str_radix(s.get(0..4)?, 16).ok()?;
    if s.get(4..6)? != "  " {
        return None;
    }
    let name = s.get(6..)?.trim_end();
    (!name.is_empty()).then_some((id, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real lines from the linux-usb.org usb.ids format, incl. a trailing
    // non-vendor section whose product line must NOT leak to the prior vendor.
    const FIXTURE: &str = "# comment line\n\
0781  SanDisk Corp.\n\
\t0001  SDDR-05a ImageMate CompactFlash Reader\n\
\t0002  SDDR-31 ImageMate II CompactFlash Reader\n\
0951  Kingston Technology\n\
\t1666  DataTraveler 100 G3/G4\n\
C 00  (Defined at Interface level)\n\
\t01  Audio\n";

    #[test]
    fn parses_vendor_name() {
        let db = UsbIdDb::parse(FIXTURE);
        assert_eq!(db.vendor_name(0x0781), Some("SanDisk Corp."));
    }

    #[test]
    fn parses_product_name() {
        let db = UsbIdDb::parse(FIXTURE);
        assert_eq!(
            db.product_name(0x0781, 0x0001),
            Some("SDDR-05a ImageMate CompactFlash Reader")
        );
    }

    #[test]
    fn unknown_vendor_is_none() {
        let db = UsbIdDb::parse(FIXTURE);
        assert_eq!(db.vendor_name(0xFFFF), None);
    }

    #[test]
    fn section_products_do_not_leak_to_previous_vendor() {
        // `\t01 Audio` sits under `C 00` (an interface-class section), not under
        // Kingston — it must not become Kingston product 0x0001.
        let db = UsbIdDb::parse(FIXTURE);
        assert_eq!(db.product_name(0x0951, 0x0001), None);
        assert_eq!(
            db.product_name(0x0951, 0x1666),
            Some("DataTraveler 100 G3/G4")
        );
    }

    #[test]
    fn comment_and_blank_lines_ignored() {
        let db = UsbIdDb::parse(FIXTURE);
        assert_eq!(db.vendor_count(), 2);
        assert!(!db.is_empty());
    }

    #[test]
    fn common_table_resolves_a_known_vendor() {
        let db = UsbIdDb::common();
        assert_eq!(db.vendor_name(0x0781), Some("SanDisk Corp."));
        assert!(db.vendor_count() >= 20);
    }
}
