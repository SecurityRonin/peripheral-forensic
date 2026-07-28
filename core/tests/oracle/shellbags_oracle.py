#!/usr/bin/env python3
"""Independent shellbag oracle for the peripheral-forensic BagMRU differential.

Decodes a Windows user hive's ``BagMRU`` shellbag tree with **regipy** + **libyal
pyfwsi** (the reference libfwsi shell-item parser) and prints, as JSON on stdout,
every decoded node together with any drive letter it references. This is the
independent third-party decode our own ``peripheral_core::shellbag`` walk is
reconciled against (Tier-1); it shares no code with the Rust reader.

Usage:  shellbags_oracle.py <hive-path>

Output (stdout): one tab-separated line per decoded node
    <DRIVE>\t<SHELL_TYPE>\t<PATH>
where <DRIVE> is a single upper-case drive letter or ``-`` when the node
references none. Tab-delimited (paths carry backslashes, never tabs) so the Rust
caller parses it with std only — no JSON dependency in the test.

A hive with no BagMRU (or the wrong hive type) yields **no lines** — the reader
must agree (both empty). Any import/parse failure exits non-zero so the caller
SKIPs rather than treating a broken oracle as a clean result.
"""
import logging
import re
import sys

# regipy logs a benign "key not found" at ERROR when a plugin runs against the
# wrong hive type (NTUSER plugin on a UsrClass hive); silence it so only the JSON
# result and genuine failures surface.
logging.disable(logging.CRITICAL)

# First drive-letter token (``X:``) anywhere in a reconstructed path or value.
_DRIVE = re.compile(r"([A-Za-z]):[\\/]")


def _drive_of(*fields):
    for f in fields:
        if isinstance(f, str):
            m = _DRIVE.search(f)
            if m:
                return m.group(1).upper()
    return None


def _run_plugin(hive, plugin_cls):
    plugin = plugin_cls(hive, as_json=True)
    plugin.run()
    return plugin.entries


def main(argv):
    if len(argv) != 2:
        print("usage: shellbags_oracle.py <hive-path>", file=sys.stderr)
        return 2
    hive_path = argv[1]

    from regipy.registry import RegistryHive
    from regipy.plugins.ntuser.shellbags_ntuser import ShellBagNtuserPlugin
    from regipy.plugins.usrclass.shellbags_usrclass import ShellBagUsrclassPlugin

    hive = RegistryHive(hive_path)

    raw = []
    # A given hive is either an NTUSER.DAT or a UsrClass.dat; run both plugins and
    # keep whatever decodes (each no-ops on the wrong hive type).
    for plugin_cls in (ShellBagNtuserPlugin, ShellBagUsrclassPlugin):
        try:
            raw.extend(_run_plugin(hive, plugin_cls))
        except Exception:  # noqa: BLE001 - wrong hive type / missing key: skip this plugin
            continue

    out = []
    for e in raw:
        value = e.get("value")
        path = e.get("path") or ""
        drive = _drive_of(value, path) or "-"
        shell_type = (e.get("shell_type") or "").replace("\t", " ")
        out.append(f"{drive}\t{shell_type}\t{path}")

    if out:
        sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
