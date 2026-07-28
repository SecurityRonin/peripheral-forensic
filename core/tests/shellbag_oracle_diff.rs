//! Tier-1 real-artifact differential for the `BagMRU` shellbag walk against an
//! **independent** oracle: regipy + libyal **pyfwsi** (the reference libfwsi
//! shell-item parser), which shares no code with our `shellitem` primitive.
//!
//! This closes the Tier-3 self-authored gap flagged for the shellbag walk: the
//! synthetic-hive test in `core/src/shellbag.rs` proves the walk agrees with a
//! fixture *we* encoded, so it cannot catch a decode assumption the fixture and
//! the reader share. Here we decode a **real** Windows user hive with a
//! third-party tool and reconcile.
//!
//! Env-gated: needs `SHELLBAG_TEST_HIVE` pointing at a real `NTUSER.DAT` /
//! `UsrClass.dat` **and** a `python3` with `regipy` + `pyfwsi`
//! (`pip install regipy[full]`); it SKIPs cleanly (no false pass) when either is
//! absent. Reference artifact: the DFIR Madness "Stolen Szechuan Sauce"
//! `ricksanchez` `UsrClass.dat` (MD5 `5e28f59f5414e754b4e6e4868fa9d7a0`) — see
//! `docs/validation.md` and `tests/data/README.md` for provenance + the extract
//! recipe.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

/// The drive-letter reconciliation between our BagMRU walk and the oracle. All
/// three sets are deduplicated and sorted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Recon {
    /// Drive letters our walk surfaced that the oracle also decodes (agreement).
    pub confirmed: Vec<char>,
    /// Drive letters our walk claimed that the oracle does NOT decode — a
    /// soundness break (a fabricated drive attribution). Must always be empty.
    pub false_positive: Vec<char>,
    /// Drive letters the oracle decodes that our walk missed — a completeness
    /// gap (e.g. a delegate-wrapped volume item `shellitem` does not yet reach).
    pub oracle_only: Vec<char>,
}

/// Reconcile the drive letters our BagMRU walk surfaced (`ours`; a `None` entry
/// is a volume node without a clean drive letter and contributes nothing)
/// against the oracle's decoded drive-letter set (`oracle`).
pub fn reconcile(ours: &[Option<char>], oracle: &[char]) -> Recon {
    // RED stub: returns nothing so the unit tests below fail until implemented.
    let _ = (ours, oracle);
    Recon::default()
}

// ---- unit tests for the pure reconciliation logic (always run) --------------

#[test]
fn reconcile_flags_a_drive_present_in_both_as_confirmed() {
    let r = reconcile(&[Some('Z')], &['Z']);
    assert_eq!(r.confirmed, vec!['Z']);
    assert!(r.false_positive.is_empty());
    assert!(r.oracle_only.is_empty());
}

#[test]
fn reconcile_flags_our_drive_absent_from_oracle_as_a_false_positive() {
    // We claim E: but the oracle's independent decode has no E: -> soundness break.
    let r = reconcile(&[Some('E')], &['Z']);
    assert_eq!(r.false_positive, vec!['E']);
    assert!(r.confirmed.is_empty());
    assert_eq!(r.oracle_only, vec!['Z']);
}

#[test]
fn reconcile_reports_oracle_only_drives_as_a_completeness_gap() {
    // The ricksanchez case: we surface Z:, the oracle surfaces Z: and E: (E: is a
    // delegate-wrapped volume our shellitem primitive does not yet decode).
    let r = reconcile(&[Some('Z')], &['Z', 'E']);
    assert_eq!(r.confirmed, vec!['Z']);
    assert!(r.false_positive.is_empty());
    assert_eq!(r.oracle_only, vec!['E']);
}

#[test]
fn reconcile_ignores_none_entries_and_deduplicates() {
    // None entries (nameless library volumes) carry no drive letter; repeats collapse.
    let r = reconcile(&[None, Some('Z'), Some('Z'), None], &['Z', 'Z']);
    assert_eq!(r.confirmed, vec!['Z']);
    assert!(r.false_positive.is_empty());
    assert!(r.oracle_only.is_empty());
}

#[test]
fn reconcile_of_two_empty_sets_is_clean() {
    assert_eq!(reconcile(&[], &[]), Recon::default());
}

// ---- the env-gated real-artifact differential -------------------------------

#[test]
fn bagmru_walk_matches_the_regipy_pyfwsi_oracle() {
    let Ok(hive_path) = std::env::var("SHELLBAG_TEST_HIVE") else {
        eprintln!("SKIP: set SHELLBAG_TEST_HIVE to a real NTUSER.DAT / UsrClass.dat");
        return;
    };
    let Some(oracle_drives) = run_oracle(&hive_path) else {
        eprintln!(
            "SKIP: python3 with regipy + pyfwsi unavailable (pip install regipy[full]); \
             cannot run the independent oracle"
        );
        return;
    };

    let hive = winreg_core::hive::Hive::from_path(std::path::Path::new(&hive_path))
        .expect("valid REGF hive");
    let ours = peripheral_core::shellbag::parse_shellbags(&hive, "shellbag-oracle-diff");
    let our_drives: Vec<Option<char>> = ours.iter().map(|e| e.drive_letter).collect();

    let r = reconcile(&our_drives, &oracle_drives);

    // SOUNDNESS (hard gate): every drive letter our BagMRU walk reports is
    // confirmed by the independent libfwsi decode. A false positive means our
    // reader fabricated a drive attribution the reference tool does not see.
    assert!(
        r.false_positive.is_empty(),
        "our BagMRU walk reported drive letters the oracle does not decode: {:?}\n  \
         ours={our_drives:?}\n  oracle={oracle_drives:?}",
        r.false_positive
    );

    // PATH agreement: for every confirmed drive our reconstructed path carries the
    // same `<letter>:` token the oracle attributes to that volume node.
    for d in &r.confirmed {
        assert!(
            ours.iter().any(|e| {
                e.drive_letter == Some(*d) && e.path.to_ascii_uppercase().contains(&format!("{d}:"))
            }),
            "confirmed drive {d}: has no matching `{d}:` token in our reconstructed path"
        );
    }

    // COMPLETENESS gap (informational, non-fatal): drive letters the oracle
    // decodes that our shellitem primitive does not yet reach — delegate-wrapped
    // volume items, e.g. the ricksanchez `E:` browsed with FTK Imager. Surfaced,
    // not asserted-away; tracked in docs/validation.md "Known gap".
    if !r.oracle_only.is_empty() {
        eprintln!(
            "KNOWN GAP (docs/validation.md): oracle decoded drive letters our walk missed: {:?}",
            r.oracle_only
        );
    }
    eprintln!(
        "differential OK — confirmed drives {:?}; oracle total drive refs {oracle_drives:?}",
        r.confirmed
    );
}

/// Run the bundled independent oracle (`tests/oracle/shellbags_oracle.py`) over
/// `hive_path` and return its decoded drive-letter set, or `None` when the oracle
/// cannot run (interpreter or `regipy`/`pyfwsi` missing) so the caller SKIPs
/// rather than treating a broken oracle as a clean (empty) result.
fn run_oracle(hive_path: &str) -> Option<Vec<char>> {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/oracle/shellbags_oracle.py"
    );
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg(hive_path)
        .output()
        .ok()?;
    if !output.status.success() {
        eprintln!(
            "oracle failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let drives: BTreeSet<char> = stdout
        .lines()
        .filter_map(|line| line.split('\t').next())
        .filter_map(|d| d.chars().next())
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    Some(drives.into_iter().collect())
}
