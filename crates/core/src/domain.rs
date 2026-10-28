use serde::{Deserialize, Serialize};

/// The independently-routable data domains — originally defined in `discovery-db`
/// (2026-08-18 multi-DB routing, 8 domains at the time) for `DomainRouting`; moved here
/// 2026-08-21 so `discovery-web`'s per-domain read/write permission checks
/// (`discovery_auth`) can name a domain without depending on `discovery-db` itself, which
/// pulls in the ClickHouse/Cassandra clients purely for storage routing — dependencies
/// this crate's own docs promise to stay free of ("Zero dependency on siblings on
/// purpose"). `discovery-db` re-exports this type (`pub use discovery_core::Domain`) so
/// its existing callers (`main.rs`, `discovery_logging::store`) are unaffected. Grew a 9th
/// domain 2026-09-07 (`MaintenanceWindows`) — see that variant's own docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Domain {
    Settings,
    Alerts,
    Devices,
    DiscoveryConfigs,
    DeviceMetrics,
    Profiles,
    Logs,
    Jobs,
    /// Maintenance windows (2026-09-07, direct user request — "Maintenance windows...
    /// с настройкой, указанием cidr, профилей"): a named, independently CRUD-able
    /// resource (`discovery_config_store::MaintenanceWindowStore`), same shape as
    /// `DiscoveryConfigs`/`Profiles` — a 9th domain, not folded into an existing one, so
    /// it gets its own routable storage location and RBAC permission, following the
    /// exact same pattern every other domain here already does.
    MaintenanceWindows,
    /// Notification matrix rules (`discovery_config_store::NotificationRule`) *and* the
    /// system-wide SMTP/Telegram provider config (`discovery_core::NotificationProviderConfig`,
    /// a `SettingsStore` category) — 2026-09-10, direct user request "Реализуй каналы
    /// нотификации + матрицу нотификации". Deliberately covers *both* resources under one
    /// domain rather than splitting the provider config into `Settings`: a holder of this
    /// domain should be able to configure who gets paged *and* how (SMTP/bot credentials)
    /// without needing the broader `Settings` grant (which also covers unrelated DB
    /// routing/retention config). Per-user notification *channels*
    /// (`discovery_core::NotificationChannel`) are deliberately **not** gated by this
    /// domain at all — they're self-service, same tier as `PUT /api/auth/password`.
    Notifications,
    /// Topology (`discovery_config_store::TopologyRule` + `discovery_topology::TopologyStore`)
    /// — 2026-09-16, direct user request: rebuilding the topology feature (deleted whole
    /// 2026-09-15, see `docs/Roadmap.md`) around provider-authored Rhai extraction rules
    /// instead of a hardcoded protocol (LLDP/CDP/...), since this product is sold to many
    /// providers with very different network gear/conventions. Covers *both* the rule
    /// config (`topology_rules`) and the derived per-device data
    /// (`topology_device_keys`/`topology_claims`) under one domain — same "one small
    /// feature, one domain covering its own config + data" shape as `MaintenanceWindows`/
    /// `Notifications`, not split across two grants.
    Topology,
    /// Group-alert suppression rules (`discovery_config_store::GroupAlertRule`) — 2026-09-16,
    /// item 3 of `docs/Roadmap.md`'s "Топология → групповые тревоги → RADIUS" chain,
    /// direct user request. Config-only (12th domain): unlike `Topology`, there is no
    /// separate "derived per-device data" table this domain also covers — the correlation
    /// result (`Alert::suppressed_by_alert_id`) is written onto the `alerts` table, which
    /// stays under `Domain::Alerts` since it's still fundamentally alert data, not
    /// group-alert-rule data. Same "one small feature, one domain" precedent as
    /// `MaintenanceWindows`/`Notifications`/`Topology`.
    GroupAlerts,
}

impl Domain {
    pub const ALL: [Domain; 12] = [
        Domain::Settings,
        Domain::Alerts,
        Domain::Devices,
        Domain::DiscoveryConfigs,
        Domain::DeviceMetrics,
        Domain::Profiles,
        Domain::Logs,
        Domain::Jobs,
        Domain::MaintenanceWindows,
        Domain::Notifications,
        Domain::Topology,
        Domain::GroupAlerts,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Domain::Settings => "settings",
            Domain::Alerts => "alerts",
            Domain::Devices => "devices",
            Domain::DiscoveryConfigs => "discovery_configs",
            Domain::DeviceMetrics => "device_metrics",
            Domain::Profiles => "profiles",
            Domain::Logs => "logs",
            Domain::Jobs => "jobs",
            Domain::MaintenanceWindows => "maintenance_windows",
            Domain::Notifications => "notifications",
            Domain::Topology => "topology",
            Domain::GroupAlerts => "group_alerts",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "settings" => Domain::Settings,
            "alerts" => Domain::Alerts,
            "devices" => Domain::Devices,
            "discovery_configs" => Domain::DiscoveryConfigs,
            "device_metrics" => Domain::DeviceMetrics,
            "profiles" => Domain::Profiles,
            "logs" => Domain::Logs,
            "jobs" => Domain::Jobs,
            "maintenance_windows" => Domain::MaintenanceWindows,
            "notifications" => Domain::Notifications,
            "topology" => Domain::Topology,
            "group_alerts" => Domain::GroupAlerts,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_str_roundtrip() {
        for domain in Domain::ALL {
            assert_eq!(
                Domain::from_str(domain.as_str()),
                Some(domain),
                "roundtrip failed for {domain:?}"
            );
        }
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert_eq!(Domain::from_str("bogus"), None);
    }
}
