# peripheral-forensic test corpus

Per the fleet corpus-catalog standard: every fixture is either a **real**
artifact (with provenance) or a **synthetic / spec-exact** one (with the
authoritative grammar it matches and the verbatim way to capture a genuine one).
No real person's device-installation log is ever committed.

Cross-reference: the single machine-index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen/blob/main/docs/corpus-catalog.md);
this README is the co-located human-facing detail.

## Fixtures

### `synthetic_usb_system.hive` — SYNTHETIC (generated, `✓` confirmed)

An 8 KB in-memory REGF `SYSTEM` hive (md5 `c3f6090c6948f32e962908d66973a5d9`)
holding three device instances that exercise every branch of the `registry`
decoder deterministically in CI: an `Enum\SCSI` disk (`0064` first-install +
`0066` last-arrival FILETIMEs, UTF-16 `FriendlyName`, OS-generated serial), an
`Enum\USBSTOR` disk (first-install via the `0065` fallback + `0067` last-removal,
no `FriendlyName`), and an `Enum\USB` device (`VID_0781&PID_5583`, real iSerial).

**Generator** (verbatim): built with `winreg-testutil`'s `TestHiveBuilder`
(`add_key` / `add_value(key, name, type, data)` with FILETIME = `(epoch +
11_644_473_600) * 10_000_000` little-endian, `FriendlyName` as UTF-16LE) — the
source lives at `docs/` build notes; regenerate by rerunning that builder. This
is a **Tier-3 coverage fixture**: the decoder's *correctness* is validated at
**Tier-1** by `core/tests/registry_real_hive.rs` against the real DFIR Madness
"Szechuan Sauce" `SYSTEM` hive, cross-checked with the independent **regipy**
oracle (env-gated on `PERIPHERAL_TEST_SYSTEM_HIVE`). `winreg-core` reads this
hive; regipy's stricter traversal does not, which is why it is coverage-only.

### `synthetic_emdmgmt.hive` — SYNTHETIC (generated, `✓` confirmed)

An 8 KB in-memory REGF `SOFTWARE` hive (md5 `f5f2515237d82dde55d764615014b575`)
covering the `EMDMgmt` volume label+serial reader in CI:
`Microsoft\Windows NT\CurrentVersion\EMDMgmt\` with one labelled volume subkey
(`PFX__TESTUSB_1234567890` → label `TESTUSB`, serial `1234567890`) and a
`NoSerialHere` subkey (no trailing decimal serial → skipped).

**Generator** (verbatim): `winreg-testutil`'s `TestHiveBuilder`, `add_key` for the two
EMDMgmt subkeys (the record is the subkey NAME; no values needed). **Tier-3 coverage
fixture**: the same decode is validated **Tier-1** by
`cfreds_emdmgmt_recovers_the_usb_volume_labels_and_serials` in
`core/tests/registry_real_hive.rs` against the real **NIST CFReDS Data-Leakage** SOFTWARE
hive, where EMDMgmt caches both SanDisk sticks — `Authorized USB` (serial 1551191358) and
`IAMAN $_@` (serial 2657770370), the NIST answer-key labels
(env var `PERIPHERAL_TEST_WIN7_SOFTWARE`).

### `synthetic_mountpoints2.hive` — SYNTHETIC (generated, `✓` confirmed)

An 8 KB in-memory REGF `NTUSER.DAT` hive (md5 `af350f7c7e0597699058b757328b8963`)
covering the `MountPoints2` per-user mount reader deterministically in CI:
`Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\` with one
volume-GUID subkey (`{a2f2048e-…}`, key last-write epoch `1_427_230_953` =
2015-03-24 21:02:33 UTC) and a `##server#share` UNC entry (not a `{GUID}` → skipped).

**Generator** (verbatim): `winreg-testutil`'s `TestHiveBuilder` with `with_key_times`
(FILETIME = `(epoch + 11_644_473_600) * 10_000_000`) and `add_key` for the two
MountPoints2 subkeys. **Tier-3 coverage fixture**: the same decode is validated
**Tier-1** by `cfreds_mountpoints2_records_the_informants_usb_volume_mount` in
`core/tests/registry_real_hive.rs` against the real **NIST CFReDS Data-Leakage** informant
`NTUSER.DAT` (Windows 7), where the user mounted `{a2f2048e-…}` — tied by the
`MountedDevices` MBR bridge to drive `E:` (label `IAMAN $_@`) — the per-user half of
the USB-exfil attribution (env var `PERIPHERAL_TEST_WIN7_NTUSER`).

### `synthetic_volume_info_cache.hive` — SYNTHETIC (generated, `✓` confirmed)

An 8 KB in-memory REGF `SOFTWARE` hive (md5 `403723352b1f58bb17955690828903a8`)
covering the `VolumeInfoCache` volume-label reader deterministically in CI:
`Microsoft\Windows Search\VolumeInfoCache\` with `E:` labelled `TESTLABEL`, `C:`
unlabelled (`VolumeLabel` = DWORD `0`, skipped), and a bogus `ZZ:` non-drive-letter
subkey (skipped). Only `E:` yields a record.

**Generator** (verbatim): `winreg-testutil`'s `TestHiveBuilder` — `add_key` for each
`VolumeInfoCache\<name>` and `add_value("VolumeLabel", REG_SZ, <UTF-16LE>)` (or a DWORD
`0` for the unlabelled case). **Tier-3 coverage fixture**: the same decode is validated
**Tier-1** by `cfreds_volume_info_cache_recovers_the_usb_volume_label` in
`core/tests/registry_real_hive.rs` against the real **NIST CFReDS Data-Leakage** SOFTWARE
hive (Windows 7), where drive `E:` carries the SanDisk stick's label `IAMAN $_@` —
matching the published NIST answer key (env var `PERIPHERAL_TEST_WIN7_SOFTWARE`; the
challenge image is not redistributed).

### `synthetic_win7_props.hive` — SYNTHETIC (generated, `✓` confirmed)

An 8 KB in-memory REGF `SYSTEM` hive (md5 `032bb05b9cb9d6c7515d867c6f0764f3`)
covering the **Windows 7** device-property FILETIME layout deterministically in CI: one
`USBSTOR` device whose install FILETIME lives at
`Properties\{83da6326-…}\00000064\00000000` in a `Data` REG_BINARY value (8-hex property
name + nested `00000000` leaf), the older layout distinct from the modern
`{GUID}\0064`-default-value form. Decodes to epoch `1_427_135_471` (2015-03-23
18:31:11 UTC).

**Generator** (verbatim): `winreg-testutil`'s `TestHiveBuilder` — `add_key` for
`ControlSet001\Enum\USBSTOR\Disk&Ven_Test&Prod_W7\7&win7serial&0` and its
`Properties\{83da6326-…}\00000064\00000000` leaf, `add_value("Data", REG_BINARY,
<FILETIME LE>)` with `FILETIME = (epoch + 11_644_473_600) * 10_000_000`. **Tier-3
coverage fixture**: the same Win7 decode is validated **Tier-1** by
`win7_usbstor_device_property_filetimes_are_decoded` in `core/tests/registry_real_hive.rs`
against the real **NIST CFReDS Data-Leakage** SYSTEM hive (Windows 7), whose SanDisk
Cruzer Fit devices' install times match the published NIST answer key
(env var `PERIPHERAL_TEST_WIN7_SYSTEM`; the challenge image is not redistributed).

### `synthetic_mounted_devices.hive` — SYNTHETIC (generated, `✓` confirmed)

An 8 KB in-memory REGF `SYSTEM` hive (md5 `7f9e5d24dda47697131202a45d34e25a`)
covering both the `MountedDevices` drive-letter join and the MBR-record volume
bridge deterministically in CI: one `Enum\SCSI` device instance (`5&join123&0`)
plus a `MountedDevices` key with four REG_BINARY values — `\DosDevices\E:` → the
UTF-16LE device path naming that instance (the drive-letter join → `E:`), a
12-byte MBR record under `\DosDevices\C:` (disk signature `0x44332211` + offset;
decoded by `mounted_volumes`), a `\??\Volume{…}` device path (a volume GUID
device path, not an MBR record), and a bogus `\GLOBAL??\BogusLink` mount name
(neither a drive letter nor a volume GUID → skipped by `mounted_volumes`).

**Generator** (verbatim): `winreg-testutil`'s `TestHiveBuilder` —
`add_key("ControlSet001\Enum\SCSI\Disk&Ven_Test&Prod_X\5&join123&0")` and a
`MountedDevices` key with the three `add_value(name, REG_BINARY, data)` entries
above (device paths UTF-16LE-encoded, no NUL terminator). **Tier-3 coverage
fixture**: correctness is validated at **Tier-1** by
`mounted_devices_joins_drive_letter_d_to_the_cdrom_device` in
`core/tests/registry_real_hive.rs` against the real Szechuan `SYSTEM` hive
(regipy oracle: `\DosDevices\D:` → the CD-ROM device instance).

### `setupapi.dev.log` — SYNTHETIC (spec-exact, `✓` confirmed)

A hand-authored Vista+ `setupapi.dev.log` matching the Microsoft SetupAPI
text-log grammar. It contains five device-install section headers exercising the
analyzer end-to-end in `forensic/tests/real_data.rs`:

- a USB flash drive (`USB\VID_0781&PID_5583\…`, real iSerial) — mass storage,
- a USBSTOR disk (`USBSTOR\Disk&Ven_SanDisk&…`) — mass storage,
- a 1394 FireWire camera (`1394\…`) — DMA-capable (T1200),
- a HID device (`HID\VID_046D&PID_C52B&…`, OS-generated `7&…&0` serial) — BadUSB
  lens + OS-generated serial,
- a PCI device (`PCI\VEN_8086&…`, OS-generated `3&…&FE` serial) — DMA-capable +
  OS-generated serial.

**Spec citation:** Microsoft Learn — *SetupAPI Text Logs* and *Format of a Text
Log Section Header*
(<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-text-logs>);
USB device-id grammar `USB\VID_v(4)&PID_d(4)&REV_r(4)` from *Standard USB
Identifiers*
(<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/standard-usb-identifiers>);
the OS-generated-serial rule (2nd character `&`) from *Instance IDs*
(<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/instance-ids>).

### `setupapi_xp.log` — SYNTHETIC (spec-exact, `✓` confirmed)

A hand-authored XP-format `setupapi.log` (timestamp-first header grammar) with
two `Device Install -` lines (a Samsung USB device and a Kingston USBSTOR disk),
matching the same Microsoft grammar.

## Capturing a genuine `setupapi.dev.log`

The build host is macOS and has no `setupapi.dev.log`. To validate against a real
one:

1. On a Windows VM, plug in a USB / FireWire / Thunderbolt device.
2. Copy `C:\Windows\INF\setupapi.dev.log` (Vista+) — or `C:\Windows\setupapi.log`
   on XP — off the host.
3. Run `parse_setupapi(&std::fs::read_to_string(path)?, "setupapi.dev.log")`.

Never commit a real person's `setupapi.dev.log` — it embeds the serial numbers of
every device they ever attached. Redact or regenerate before sharing.

### Linux syslog — REAL (env-gated, not committed)

The Linux kernel-log reader is validated against a genuine UAC (Unix-like Artifacts
Collector) `syslog` from the **HAL Linux DFIR challenge** (issen corpus:
`hal-linux-dfir-challenge/uac-vbox-linux-*.tar.gz`, extract to `/tmp`). The env-gated
test `core/tests/linux_syslog_real.rs` (`LINUX_SYSLOG_PATH`) confirms it extracts the
real VirtualBox USB Tablet (`idVendor=80ee, idProduct=0021`, "USB Tablet") and root
hubs (`idVendor=1d6b`). The archive is large and lives in the issen corpus, not here.

### `synthetic_thunderbolt.hive` — SYNTHETIC (generated, `✓` confirmed)

An 8 KB in-memory REGF `SYSTEM` hive (md5 `52bfdb21c9e1472d4205e30f1eb775de`) with one `Enum\THUNDERBOLT`
device instance (`VEN_TB&DEV_DOCK\TB0001`, `FriendlyName` "CalDigit TS4 Dock",
a `0066` last-arrival FILETIME under `Properties\{83da6326-97a6-4088-9453-a1923f573b29}`),
exercising the `Enum\THUNDERBOLT` branch of the `registry` walker — a Thunderbolt
connection is a bus-mastering **DMA-capable** device (`PERIPHERAL-DMA-CAPABLE-DEVICE`).

**Generator** (verbatim): `winreg-testutil`'s `TestHiveBuilder` — `add_key` for the
`THUNDERBOLT\VEN_TB&DEV_DOCK\TB0001` instance + its `Properties\{83da6326…}\0066` prop
subkey; `add_value` for `FriendlyName` (REG_SZ, UTF-16LE) and the `0066` default value
(REG_BINARY, 8-byte LE FILETIME = `(unix + 11_644_473_600) * 10_000_000`). **Tier-3
coverage fixture**: the property-store decode is bus-agnostic and validated **Tier-1** by
`vmware_scsi_disk_matches_regipy_ground_truth` against the real Szechuan `SYSTEM` hive +
regipy oracle; this fixture only exercises the added `THUNDERBOLT` enum class.

### `synthetic_bagmru.hive` — SYNTHETIC (generated, `✓` confirmed)

An 8 KB in-memory REGF `NTUSER.DAT` hive (md5 `6a45688df5d8afe0d21508a127d571c4`)
covering the `shellbag` `BagMRU` reader deterministically in CI. Its tree is
`Software\Microsoft\Windows\Shell\BagMRU` → `0` (My Computer) → `0` (`E:\`) → `0`
(`photos`), with each slot's shell-item bytes stored in its **parent** key's
`REG_BINARY` value named by the child index (`"0"`), plus a `MRUListEx` value and a
non-numeric `Foo` sibling subkey the walker must skip. All key last-writes are epoch
`1_600_000_000` (2020-09-13 12:26:40 UTC).

The three slot values are **genuine libfwsi shell items** (not a synthetic guess),
independently validated by the fleet's fuzzed `shellitem` primitive:
- root `0x1F` — My-Computer GUID `20D04FE0-3AEA-1069-A2D8-08002B30309D`;
- volume `0x2F` — a 20-byte ASCII drive-letter name `E:\`;
- file-entry `0x31` — a directory with the short name `photos`.

**Generator** (verbatim): `winreg-testutil`'s `TestHiveBuilder` (`with_key_times` for
the FILETIME, `add_key` for the four BagMRU nodes + the `Foo` sibling, `add_value`
REG_BINARY for the three slot shell items + `MRUListEx`). The shell-item byte layouts
follow libyal `libfwsi` (root sort+GUID at offset 4; `0x2F` volume name at offset 3;
`0x31` size@4/modified@8/attrs@12/ASCII-short-name@14). **Tier-3 coverage fixture**:
correctness of the *shell-item decode* is validated **Tier-1** by `shellitem`'s own
libfwsi-referenced tests + fuzzing; this fixture exercises the `BagMRU` tree walk and
drive-letter surfacing over `winreg-core`.
