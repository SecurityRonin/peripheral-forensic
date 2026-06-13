#![no_main]
//! Full parse → audit pipeline over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let devices = peripheral_core::setupapi::parse_setupapi(&text, "fuzz");
    let _ = peripheral_forensic::audit_findings(&devices, "fuzz");
});
