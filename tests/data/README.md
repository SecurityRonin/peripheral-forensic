# peripheral-forensic test corpus

Per the fleet corpus-catalog standard: every fixture is either a **real**
artifact (with provenance) or a **synthetic / spec-exact** one (with the
authoritative grammar it matches and the verbatim way to capture a genuine one).
No real person's device-installation log is ever committed.

Cross-reference: the single machine-index is
[`issen/docs/corpus-catalog.md`](https://github.com/SecurityRonin/issen/blob/main/docs/corpus-catalog.md);
this README is the co-located human-facing detail.

## Fixtures

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
