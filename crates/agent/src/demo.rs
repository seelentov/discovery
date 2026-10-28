//! Seed data for the demo binary and tests — virtual devices behind a `FakeSnmpClient`,
//! no real network involved. Shared between `main.rs` (so `cargo run` produces something
//! to look at on the dashboard) and the test suite (so tests exercise exactly the same
//! fixture). OIDs here match `crates/agent/tests/e2e.rs`'s `demo_profiles()`.

use discovery_snmp::{FakeSnmpClient, SnmpValue};

pub fn demo_device_ips() -> Vec<String> {
    vec![
        "10.0.0.11".to_string(),
        "10.0.0.12".to_string(),
        "10.0.0.13".to_string(),
    ]
}

pub fn seed_demo_devices() -> FakeSnmpClient {
    let snmp = FakeSnmpClient::new();

    // 10.0.0.11: matches `generic_switch`, CPU is over the alert threshold (92 > 85).
    seed_identity(
        &snmp,
        "10.0.0.11",
        "1.3.6.1.4.1.9.1.1",
        "Cisco IOS Switch",
        "sw-demo-1",
        "SN-11",
        "AA:BB:CC:00:00:11",
    );
    snmp.seed_get(
        "10.0.0.11",
        "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1",
        SnmpValue::Integer(92),
    );
    snmp.seed_get(
        "10.0.0.11",
        "1.3.6.1.2.1.1.3.0",
        SnmpValue::TimeTicks(123_456),
    );

    // 10.0.0.12: same profile, healthy CPU (14) — no alert should fire.
    seed_identity(
        &snmp,
        "10.0.0.12",
        "1.3.6.1.4.1.9.1.1",
        "Cisco IOS Switch",
        "sw-demo-2",
        "SN-12",
        "AA:BB:CC:00:00:12",
    );
    snmp.seed_get(
        "10.0.0.12",
        "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1",
        SnmpValue::Integer(14),
    );
    snmp.seed_get(
        "10.0.0.12",
        "1.3.6.1.2.1.1.3.0",
        SnmpValue::TimeTicks(999_999),
    );

    // 10.0.0.13: doesn't match the switch profile, falls through to `generic_host`;
    // uptime == 0 trips that profile's `device_unreachable` alert.
    seed_identity(
        &snmp,
        "10.0.0.13",
        "1.3.6.1.4.1.99999.1",
        "Generic Host",
        "host-demo-3",
        "SN-13",
        "AA:BB:CC:00:00:13",
    );
    snmp.seed_get("10.0.0.13", "1.3.6.1.2.1.1.3.0", SnmpValue::TimeTicks(0));

    snmp
}

fn seed_identity(
    snmp: &FakeSnmpClient,
    ip: &str,
    sys_object_id: &str,
    sys_descr: &str,
    sys_name: &str,
    serial_number: &str,
    mac_address: &str,
) {
    snmp.seed_get(
        ip,
        "1.3.6.1.2.1.1.2.0",
        SnmpValue::ObjectId(sys_object_id.to_string()),
    );
    snmp.seed_get(
        ip,
        "1.3.6.1.2.1.1.1.0",
        SnmpValue::OctetString(sys_descr.to_string()),
    );
    snmp.seed_get(
        ip,
        "1.3.6.1.2.1.1.5.0",
        SnmpValue::OctetString(sys_name.to_string()),
    );
    // serial_number/mac_address — ordinary profile-polled metrics (`generic_switch`/
    // `generic_host`'s `[metrics.poll]`), not dedup-specific.
    snmp.seed_get(
        ip,
        "1.3.6.1.2.1.47.1.1.1.1.11.1",
        SnmpValue::OctetString(serial_number.to_string()),
    );
    snmp.seed_get(
        ip,
        "1.3.6.1.2.1.2.2.1.6.1",
        SnmpValue::OctetString(mac_address.to_string()),
    );
}
