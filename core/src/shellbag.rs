//! ShellBags: decode `BagMRU` folder-navigation history from a Windows user hive.
//!
//! Windows records every folder a user browses in Explorer as a `BagMRU` tree.
//! Two hives carry it: `NTUSER.DAT`
//! (`Software\Microsoft\Windows\Shell\BagMRU`) and the per-user `UsrClass.dat`
//! (`Local Settings\Software\Microsoft\Windows\Shell\BagMRU`). Each node is a
//! folder; the shell-item bytes for a child folder live in the **parent** key as
//! a `REG_BINARY` value named with the child's numeric slot ("0", "1", …). The
//! full browsed path to a node is the sequence of shell items collected walking
//! from the root down to it.
//!
//! For USB forensics the interesting subset is folders browsed on a **removable /
//! drive-letter volume** (a [`ShellItemKind::Volume`] item in the path, e.g.
//! `E:\`): a shellbag entry attests that `E:\some\folder` was browsed, which
//! corroborates that the volume was mounted at that letter and names the
//! directories touched on it. This decoder walks the tree, delegates shell-item
//! parsing to the fuzzed [`shellitem`] primitive, reconstructs the path, and
//! surfaces one [`ShellbagEntry`] per drive-letter-referencing node.
//!
//! This is a reader (no findings): the forensic correlation (tying the drive
//! letter to the physical device that carried it) lives in `usb-forensic`.
//!
//! # Robustness
//!
//! The hive is attacker-controllable. Parsing is panic-free: shell-item decoding
//! is bounds-checked by `shellitem`, the tree walk is iterative (no native
//! recursion, so no stack overflow), and a visited-offset set guarantees
//! termination on a crafted cyclic hive (a valid REGF hive is a tree).

use crate::Provenance;
use shellitem::{parse_idlist, reconstruct_path, ShellItem, ShellItemKind};
use std::collections::HashSet;
use std::io::Cursor;
use winreg_core::hive::Hive;
use winreg_core::key::Key;

/// The two `BagMRU` roots: `NTUSER.DAT` (`Software\...\Shell\BagMRU`) and the
/// per-user `UsrClass.dat` (`Local Settings\Software\...\Shell\BagMRU`).
const BAGMRU_PATHS: &[&str] = &[
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
];

/// One browsed folder from a `BagMRU` tree that references a drive-letter volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellbagEntry {
    /// The reconstructed browsed path (e.g. `My Computer\E:\\photos`), joined from
    /// the shell items on the path from the root to this node.
    pub path: String,
    /// The drive letter of the volume item in the path, upper-cased (e.g. `E`);
    /// `None` when the volume item carried no clean drive-letter name.
    pub drive_letter: Option<char>,
    /// The node key's last-written time (when the folder's shellbag was last
    /// updated), epoch seconds UTC; `None` when the hive recorded none.
    pub last_write: Option<i64>,
    /// Where the record was decoded from.
    pub source: Provenance,
}

/// Parse drive-letter `BagMRU` shellbag entries from an already-opened user hive
/// (`NTUSER.DAT` or `UsrClass.dat`). `file` is recorded on each record's
/// [`Provenance`]. Total over a valid hive — never panics.
#[must_use]
pub fn parse_shellbags(hive: &Hive<Cursor<Vec<u8>>>, file: &str) -> Vec<ShellbagEntry> {
    let mut out = Vec::new();
    for &root_path in BAGMRU_PATHS {
        let Ok(Some(root)) = hive.open_key(root_path) else {
            continue;
        };
        walk(root, root_path, file, &mut out);
    }
    out
}

/// Iterative depth-first walk of one `BagMRU` tree. Each stack frame carries the
/// node key, the shell items accumulated from the root to it, and its key path.
/// The shell-item bytes for a child slot live in the **parent** key's value named
/// by the child index, so a child's full path is the parent's items plus that
/// slot's item. A visited-offset set guarantees termination if a crafted hive is
/// cyclic (a valid REGF hive is a tree, so it never revisits).
fn walk(root: Key<'_>, root_path: &str, file: &str, out: &mut Vec<ShellbagEntry>) {
    let mut visited: HashSet<u32> = HashSet::new();
    let mut stack: Vec<(Key<'_>, Vec<ShellItem>, String)> =
        vec![(root, Vec::new(), root_path.to_string())];
    while let Some((key, parent_items, key_path)) = stack.pop() {
        if !visited.insert(key.offset().0) {
            continue; // cov:unreachable: only a crafted cyclic hive revisits a cell; a valid tree hive never does
        }
        let Ok(subkeys) = key.subkeys() else {
            continue; // cov:unreachable: subkeys() only errors on hive corruption
        };
        for sub in subkeys {
            let name = sub.name();
            // BagMRU child slots are numeric ("0", "1", …); skip any non-slot
            // sibling (e.g. a stray key that is not an ITEMIDLIST index).
            if name.parse::<u32>().is_err() {
                continue;
            }
            let bytes = key
                .value(&name)
                .ok()
                .flatten()
                .and_then(|v| v.raw_data().ok())
                .unwrap_or_default();
            let mut items = parent_items.clone();
            items.extend(parse_idlist(&bytes));
            let sub_path = format!("{key_path}\\{name}");
            if let Some(entry) = volume_entry(&items, &sub, &sub_path, file) {
                out.push(entry);
            }
            stack.push((sub, items, sub_path));
        }
    }
}

/// Build a [`ShellbagEntry`] for a node whose reconstructed path references a
/// drive-letter volume; `None` when no [`ShellItemKind::Volume`] item is present
/// (a non-volume node such as `My Computer` or `Control Panel`).
fn volume_entry(
    items: &[ShellItem],
    key: &Key<'_>,
    key_path: &str,
    file: &str,
) -> Option<ShellbagEntry> {
    let volume = items.iter().find(|i| i.kind == ShellItemKind::Volume)?;
    Some(ShellbagEntry {
        path: reconstruct_path(items),
        drive_letter: drive_letter(volume),
        last_write: last_written_epoch(key),
        source: Provenance {
            file: file.to_string(),
            line: 0,
            key_path: Some(key_path.to_string()),
        },
    })
}

/// A key's last-written time as epoch seconds UTC; `None` when the hive recorded
/// none.
fn last_written_epoch(key: &Key<'_>) -> Option<i64> {
    Some(key.last_written()?.as_second())
}

/// The upper-cased drive letter of a volume shell item whose name is a
/// `X:`-prefixed drive string (`E:\` → `E`); `None` for a nameless (`0x2e` GUID)
/// volume or any non-`letter:` name.
fn drive_letter(volume: &ShellItem) -> Option<char> {
    let mut chars = volume.name.as_deref()?.chars();
    let letter = chars.next()?;
    (letter.is_ascii_alphabetic() && chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use winreg_core::hive::Hive;

    /// A synthetic `NTUSER` hive whose `BagMRU` tree is
    /// `Desktop → My Computer → E:\ → photos`, with each slot value holding a
    /// genuine libfwsi shell item (root / volume-0x2f / file-entry-0x31), plus a
    /// non-numeric `Foo` sibling the walker must skip. All key last-writes are
    /// epoch 1_600_000_000. See `tests/data/README.md` for the generator recipe.
    fn hive() -> Hive<Cursor<Vec<u8>>> {
        const BYTES: &[u8] = include_bytes!("../../tests/data/synthetic_bagmru.hive");
        Hive::from_bytes(BYTES.to_vec()).expect("valid REGF")
    }

    #[test]
    fn surfaces_the_volume_and_the_folder_browsed_on_it() {
        let entries = parse_shellbags(&hive(), "NTUSER.DAT");
        // Two drive-letter nodes: E:\ itself and E:\photos. The My-Computer node
        // (no volume in its path) is not surfaced.
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.drive_letter == Some('E')));

        let folder = entries
            .iter()
            .find(|e| e.path.contains("photos"))
            .expect("the browsed E:\\photos folder is surfaced");
        assert!(folder.path.contains("E:"));
        assert_eq!(folder.last_write, Some(1_600_000_000));
        assert_eq!(folder.source.file, "NTUSER.DAT");
        assert!(folder
            .source
            .key_path
            .as_deref()
            .is_some_and(|k| k.contains("BagMRU")));
    }

    #[test]
    fn a_hive_without_bagmru_yields_nothing() {
        const SYS: &[u8] = include_bytes!("../../tests/data/synthetic_usb_system.hive");
        let hive = Hive::from_bytes(SYS.to_vec()).expect("valid REGF");
        assert!(parse_shellbags(&hive, "NTUSER.DAT").is_empty());
    }
}
