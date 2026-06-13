# Security Policy

`peripheral-forensic` is designed to parse **untrusted Windows
device-installation logs** — including those acquired from compromised or
actively hostile systems. Hostile input is the expected case, not an edge case.
Robustness against crafted logs, malformed headers, and garbled encodings is a
core design goal, and we take reports of crashes, hangs, or memory-safety issues
seriously.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current release line, receives security fixes |
| < 0.1   | ❌ — pre-release, unsupported |

Security fixes are released against the latest published `0.1.x` line.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`peripheral-forensic` repository](https://github.com/SecurityRonin/peripheral-forensic/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include:

- the affected version and target triple,
- a minimal reproducing log or byte buffer (a fuzz corpus entry is ideal),
- the observed behaviour (panic, hang, excessive allocation, mis-parse) and the
  expected behaviour.

We aim to acknowledge a report within a few business days and to coordinate
disclosure once a fix is available.

## Security posture

`peripheral-forensic` is hardened against adversarial input by construction:

- **`#![forbid(unsafe_code)]`** across both crates — no `unsafe`, no C bindings,
  no FFI, anywhere.
- **No panics on malicious input** — parsing is lenient (lossy UTF-8) and
  bounds-checked; a truncated or garbled log degrades line-by-line rather than
  crashing. Arithmetic is checked or saturating.
- **No length is trusted** — VID/PID/serial extraction reads only the leading hex
  run of each field and range-checks every timestamp component.
- **Fail loud where it matters** — a genuine error surfaces with context rather
  than as a silent default or a silently-wrong parse.

### Fuzzing

Continuous fuzzing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
backs the hardening above. Two targets cover the parser that consumes
attacker-controlled bytes:

| Target | Surface |
|---|---|
| `setupapi`  | `setupapi.dev.log` / `setupapi.log` header parsing (Vista+ and XP) |
| `forensic`  | the full parse → audit pipeline |

Panics found by fuzzing are fixed and pinned as regression tests.

For how to run the targets yourself, see
[CONTRIBUTING.md](CONTRIBUTING.md#quality-gates).
