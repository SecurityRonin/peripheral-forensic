# 3. Untrusted-input safety posture: forbid(unsafe), panic-free, fuzzed

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse **attacker-controllable evidence**: a `setupapi.dev.log`
acquired from a potentially compromised host, a `SYSTEM` hive of unknown
integrity, a Linux `syslog` of arbitrary content. A malformed, truncated, or
deliberately hostile input must never crash the analyzer or read out of bounds.
Unlike the fleet's mmap-backed container readers (`ewf`, `memory-forensic`),
this repo does pure text and hive-value parsing — it has no legitimate need for
any `unsafe` block.

The fleet's Paranoid Gatekeeper standard and the global Rust lint recipe require
`forbid(unsafe)` as the default-and-goal, the `unwrap_used`/`expect_used`
panic-free denies for untrusted-input parsers, and one fuzz target per parsed
structure.

## Decision

- **`#![forbid(unsafe_code)]`** on both crate roots and
  `unsafe_code = "forbid"` in `[workspace.lints.rust]`. No FFI, no C bindings,
  no mmap — so `forbid` (not the `deny`+bounded-allow downgrade) is used, and the
  README carries the `unsafe forbidden` badge honestly.
- **Panic-free lints**: `[workspace.lints.clippy]` sets `unwrap_used = "deny"`
  and `expect_used = "deny"` for production code, with
  `allow-unwrap-in-tests`/`allow-expect-in-tests` in `clippy.toml` so tests may
  still unwrap to fail loudly.
- **Lenient degradation**: parsers process line-by-line / value-by-value and
  skip anything that does not match (`setupapi.rs` skips non-header lines;
  `registry.rs` skips malformed subkeys; `mounted_volumes.rs` skips non-MBR
  values), decoding as lossy UTF-8 rather than rejecting. Genuinely unreachable
  defensive guards carry `// cov:unreachable` markers.
- **Fuzzing**: two `cargo-fuzz` targets (`fuzz/fuzz_targets/setupapi.rs` for the
  parser, `forensic.rs` for the full parse→audit pipeline), smoke-run in
  `fuzz.yml`.

## Consequences

A crafted log or hive degrades to a partial result, never a panic — the property
fuzzing tests empirically and the lints enforce statically. One such panic was
already found and fixed by the fuzzer: `setupapi::civil_to_epoch` overflowed on
an out-of-range year, now bounded to `1..=9999` and seeded in the corpus
(commit `c55674e`). The `forbid` posture forecloses the entire memory-corruption
class by construction, which is the sharpest trust signal for an evidence parser.
