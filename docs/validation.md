# Validation

Doer-Checker evidence for `peripheral-forensic`: correctness proven against
**independent oracles** on **real-world artifacts**, not only self-authored
fixtures. Each claim is tagged by the Evidence-Based Rigor tier — *who vouches for
the ground truth*.

## Summary

| Decoder | Real artifact | Independent oracle | Tier | Status |
|---|---|---|---|---|
| Registry device keys (USBSTOR/SCSI/USB, FILETIMEs) | Szechuan `SYSTEM`; CFReDS Win7 `SYSTEM` | regipy; NIST answer key | T1 | pass |
| VolumeInfoCache / EMDMgmt labels+serials | CFReDS Win7 `SOFTWARE` | NIST answer key | T1 | pass |
| MountedDevices / MountPoints2 (drive↔GUID) | CFReDS Win7 `SYSTEM`/`NTUSER` | regipy; NIST answer key | T1 | pass |
| **ShellBags `BagMRU` walk (drive-letter surfacing)** | **Szechuan `ricksanchez` `UsrClass.dat`** | **regipy + pyfwsi (libfwsi)** | **T1** | **pass (soundness) + 1 documented gap** |

The env-gated real-artifact tests (`core/tests/registry_real_hive.rs`,
`core/tests/shellbag_oracle_diff.rs`) skip cleanly when the artifact or oracle is
absent, so CI stays green on committed bytes alone; the T1 evidence is reproduced
by setting the documented env vars.

## ShellBags `BagMRU` walk — independent differential

**What was validated.** `peripheral_core::shellbag::parse_shellbags` walks the
`BagMRU` tree of a Windows user hive and surfaces the drive-letter volumes browsed
in Explorer (the USB-attribution signal: an `E:\…` shellbag attests the volume was
mounted at that letter and names the folders touched on it). Before this pass its
only test was the synthetic `synthetic_bagmru.hive` — a fixture we encoded, so it
could only prove the walk agrees with *itself* (Tier-3; the review flagged exactly
this).

**The oracle.** `core/tests/oracle/shellbags_oracle.py` decodes the same hive with
**regipy** driving **libyal pyfwsi** (the reference `libfwsi` shell-item parser).
This is an independent third-party decode of a real-world artifact — Tier-1 — that
shares no code with our `shellitem` primitive. The Rust differential runs both,
then `reconcile()` compares the drive-letter sets.

**Reference artifact.** DFIR Madness "Stolen Szechuan Sauce" Case 001, the
`ricksanchez` `UsrClass.dat` carved from `DESKTOP-E01.zip` (extracted-file MD5
`5e28f59f5414e754b4e6e4868fa9d7a0`). Provenance + the extract recipe:
`tests/data/README.md` and `issen/docs/test-data-catalog.md` §A3/§A3b.

**Result.** The hive's `BagMRU` references three drive-letter nodes:

| Node | Oracle (libfwsi) | Our walk |
|---|---|---|
| `My Computer\Z:\` (`BagMRU\0\0`) | Volume `Z:\` → **Z** | Volume `Z:\` → **Z** ✅ (path token confirmed) |
| `E:\` (`BagMRU\2`) | Volume `E:\` → **E** | missed — decoded as a root-folder GUID (see gap) |
| `E:\FTK Imager` (`BagMRU\2\0`) | Directory on **E** | missed (its parent volume was not decoded) |

- **Soundness (hard gate, pass):** every drive letter our walk reports is confirmed
  by libfwsi — no fabricated attribution. Our `Z:` matches the oracle on both the
  drive letter and the reconstructed `Z:` path token.
- **Completeness (one documented gap):** the oracle also decodes `E:` (browsed with
  **FTK Imager**), which our walk misses.

### Known gap — delegate-wrapped volume shell items (`shellitem`)

The `E:\` node at `BagMRU\2` is a **delegate** shell item: class byte `0x1F` with an
embedded volume item (`2f 45 3a 5c` = `E:\`) and the well-known delegate-item GUID
`5e591a74-df96-48d3-8d67-1733bcee28ba`. libfwsi parses the inner item and returns a
volume `E:\`; our `shellitem` primitive decodes the outer `0x1F` as a root folder
with a spurious GUID and never reaches the inner volume, so the drive letter is
lost. This is a **`shellitem` decoder gap, not a `peripheral-forensic` walk bug** —
the walk surfaces every volume `shellitem` hands it.

The differential surfaces this as an informational `KNOWN GAP` line (it is not
asserted away, so the evidence stays visible) rather than being encoded as
"correct". Closing it belongs in the `shellitem` repo: add delegate-item decoding
(recurse into the embedded item), grounded in the `libfwsi` "Delegate" shell-item
spec — a general rule, not a one-sample patch — with its own fuzz target and a
real-artifact test over this same `E:\ / E:\FTK Imager` node. Until then, browsed
folders that Explorer recorded as delegate-wrapped volumes are not attributed a
drive letter by the walk.

## Reproduce

```sh
# 1. carve the reference hive (from the issen orchestration repo that owns the corpus)
unzip -o -j dfirmadness-szechuan-sauce/DESKTOP-E01.zip '*.E0*' -d /tmp/desktop-e01
mkdir -p /tmp/case001-hives
cargo run --release --example extract_usrclass -- \
  /tmp/desktop-e01/20200918_0417_DESKTOP-SDN1RPT.E01 /tmp/case001-hives

# 2. oracle deps (once): pip install 'regipy[full]'   (pulls pyfwsi / libfwsi)

# 3. run the differential
SHELLBAG_TEST_HIVE=/tmp/case001-hives/UsrClass-ricksanchez.dat \
  cargo test -p peripheral-core --test shellbag_oracle_diff -- --nocapture
```
