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
    #[must_use]
    pub fn parse(_text: &str) -> Self {
        Self::default() // stub — RED
    }

    /// The built-in, hand-authored table of common forensic-relevant vendors.
    #[must_use]
    pub fn common() -> Self {
        Self::default() // stub — RED
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
