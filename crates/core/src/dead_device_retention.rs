use serde::{Deserialize, Serialize};

/// Global auto-cleanup threshold for devices that have stopped answering ping — direct
/// user request 2026-08-18, following up on manual device deletion already existing in
/// the UI: "Сделай настраиваемый через конфиг период времени после которого устройство с
/// ping=false удаляется. По умолчанию сделай 0 - если 0 никогда не удалять."
///
/// **Deliberately `u64` with a `0`-means-disabled sentinel, not `Option<u64>`
/// with `None`-means-forever** — that's the opposite convention from
/// [`crate::AlertRetentionConfig`] (`Option<u64>`, `None` = keep forever), but it's what
/// the user explicitly specified here, so this type follows that instruction rather than
/// the sibling type's precedent.
///
/// One global value, not per-subnet/per-profile — same "one knob, not one per rule"
/// reasoning `AlertRetentionConfig` already documents, and nothing in the request asked
/// for finer granularity. DB-backed via `discovery_config_store::SettingsStore`
/// (`get_dead_device_retention`/`set_dead_device_retention`), same
/// live-editable-without-restart treatment as every other settings category.
///
/// Only devices with `enabled = true` are ever subject to this — see
/// `discovery_devices::DeviceStore::delete_unreachable_since`'s docs for why a device a
/// human explicitly parked (`Device::enabled = false`) is exempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DeadDeviceRetentionConfig {
    /// How long `ping_ok` must have been continuously `false`
    /// (`Device::ping_failing_since`) before the cleanup sweep deletes the device. `0`
    /// (the default) disables this entirely — nothing is ever auto-deleted.
    pub unreachable_for_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        assert_eq!(DeadDeviceRetentionConfig::default().unreachable_for_secs, 0);
    }

    #[test]
    fn round_trips_through_json() {
        let original = DeadDeviceRetentionConfig {
            unreachable_for_secs: 86400,
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: DeadDeviceRetentionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }
}
