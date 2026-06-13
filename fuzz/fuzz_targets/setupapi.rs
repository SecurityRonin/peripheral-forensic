#![no_main]
//! setupapi.dev.log parse over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = peripheral_core::setupapi::parse_setupapi(&text, "fuzz");
});
