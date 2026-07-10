//! Real-artifact validation of the Linux kernel-log USB reader against a genuine
//! UAC (Unix-like Artifacts Collector) `syslog` from the HAL Linux DFIR challenge.
//! Env-gated (`LINUX_SYSLOG_PATH`); skips cleanly when the artifact is absent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use peripheral_core::linux_syslog::parse_linux_syslog;
use peripheral_core::Bus;

#[test]
fn finds_the_real_virtualbox_usb_tablet() {
    let Ok(path) = std::env::var("LINUX_SYSLOG_PATH") else {
        eprintln!("SKIP: set LINUX_SYSLOG_PATH to a real Linux syslog");
        return;
    };
    let text = std::fs::read_to_string(&path).expect("readable syslog");
    let conns = parse_linux_syslog(&text, "syslog", 2026);

    // The VM enumerates root hubs (idVendor=1d6b) and a VirtualBox USB Tablet.
    let tablet = conns
        .iter()
        .find(|c| c.vid == Some(0x80ee) && c.pid == Some(0x0021))
        .expect("VirtualBox USB Tablet present in the real syslog");
    assert_eq!(tablet.bus, Bus::Usb);
    assert_eq!(tablet.friendly_name.as_deref(), Some("USB Tablet"));
    assert!(tablet.first_install.is_some(), "connect time parsed");

    // Root hubs are Linux Foundation devices (idVendor=1d6b) — also enumerated.
    assert!(
        conns.iter().any(|c| c.vid == Some(0x1d6b)),
        "root hubs enumerated too"
    );
}
