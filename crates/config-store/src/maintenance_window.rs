//! Maintenance windows — direct user request 2026-09-07: "Maintenance windows —
//! подавление тревог на время работ", elaborated as "Реализуй это с настройкой,
//! указанием cidr, профилей. Нужна достаточное количество параметров настройки что бы
//! взять только группу девайсов". See `docs/Architecture/Maintenance Windows.md` for the
//! full design writeup and `discovery_agent::handlers::AlertEvalHandler` for the
//! enforcement point (the actual alert-evaluation suppression gate this store feeds).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use uuid::Uuid;

use crate::scan::ipv4_in_subnet;

/// One CIDR-range target dimension of a [`MaintenanceWindow`]'s selector — the same
/// dotted-decimal ip+mask shape as [`crate::SubnetSpec`] (see that type's `mask` field
/// docs for why this project deliberately picked that representation over `a.b.c.d/nn`
/// notation: "the representation most network engineers reach for first"). Deliberately
/// its own, smaller type rather than reusing `SubnetSpec` itself — a maintenance window's
/// targeting has no use for `SubnetSpec`'s SNMP port/credentials/discovery-time
/// OIDs/labels, all of which are meaningless outside the discovery pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubnetTarget {
    pub ip: String,
    pub mask: String,
}

impl SubnetTarget {
    /// A malformed `ip`/`mask` was never rejected at REST create/edit time (SEC audit
    /// finding, 2026-09-21) — it saved with `2xx` just fine, and only failed silently
    /// later: `matches`/`matches_device`'s `ipv4_in_subnet(...).unwrap_or(false)` treats a
    /// parse error identically to "candidate genuinely outside this subnet", so a typo'd
    /// selector doesn't error, it just never matches anything, ever, with no signal
    /// pointing back at the bad row. Reuses `mask_to_prefix_len`'s exact contiguous-mask
    /// check — the same one `matches`'s own `ipv4_in_subnet` call applies — so "saves
    /// without a validation error" and "actually capable of matching something" can't
    /// drift apart again.
    ///
    /// Deliberately does **not** require `ip` to be the canonical network address (e.g.
    /// rejecting `"10.0.0.5"` with mask `"255.255.255.0"` for having host bits set):
    /// `ipv4_in_subnet` re-masks both sides of the comparison on every match, so a
    /// non-canonical `ip` here behaves identically to its canonical form — normalizing it
    /// would be cosmetic, not a correctness fix, and isn't worth the extra behavior to
    /// document/support.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.ip
            .parse::<Ipv4Addr>()
            .map_err(|e| anyhow::anyhow!("invalid ip '{}': {e}", self.ip))?;
        crate::scan::mask_to_prefix_len(&self.mask)?;
        Ok(())
    }
}

/// A one-off, time-boxed suppression window for alert evaluation — device- and
/// time-scoped sibling of `Device::enabled`/`AlertRule::enabled`'s "freeze, don't
/// force-close" convention (see `.claude/rules/engineering-patterns.md`): while a window
/// is active for a device, `AlertEvalHandler` skips that device's alert evaluation
/// entirely for the tick (no new activations, no `StillActive` persistence churn, no
/// clears) — it does not touch whatever incidents are already open.
///
/// **Recurrence (e.g. "every Sunday 2-4am") is deliberately out of scope for v1** — this
/// is always one absolute `[starts_at, ends_at]` range, not a schedule. A known future
/// extension, not built now (see the architecture doc).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaintenanceWindow {
    pub id: Uuid,
    pub name: String,
    /// Independent kill-switch — an operator can cancel a scheduled window without
    /// deleting it (work finished early, or was called off entirely). `false` means this
    /// window never suppresses anything, regardless of `starts_at`/`ends_at`.
    pub enabled: bool,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    /// Device's IP must fall inside at least one of these — empty means "don't filter by
    /// subnet" (an unset dimension never itself excludes a device).
    #[serde(default)]
    pub subnets: Vec<SubnetTarget>,
    /// Device's current profile name must be one of these — empty means "don't filter by
    /// profile".
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Explicit allow-list, for precision beyond what CIDR/profile alone can express — a
    /// device in this list matches **unconditionally**, regardless of `subnets`/
    /// `profiles` (see [`Self::matches`]'s docs for the full contract).
    #[serde(default)]
    pub device_ids: Vec<Uuid>,
}

impl MaintenanceWindow {
    /// `true` if `now` falls inside `[starts_at, ends_at]` — inclusive both ends
    /// (deliberately, not a half-open range: a window's own boundary instant should read
    /// as "already/still under maintenance", not a one-tick gap right at the edge) — and
    /// `enabled` is `true`.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.enabled && self.starts_at <= now && now <= self.ends_at
    }

    /// Does `device_id` (at `ip`, currently on profile `profile`) fall under this
    /// window's target selector? Independent of [`Self::is_active`] — callers combine
    /// both (see [`is_device_under_maintenance`]).
    ///
    /// **Selector semantics (direct user request 2026-09-07; the recommended default from
    /// the request itself, applied as-is — no `SendMessage` round-trip needed, this read
    /// as the correct interpretation of "взять только группу устройств"):**
    /// - `device_ids` is an *unconditional* match: a device in that list matches
    ///   regardless of every other dimension, populated or not — an explicit id is
    ///   already maximally precise, there's nothing left for another dimension to narrow.
    /// - Otherwise, **AND across every *populated* dimension** among `subnets`/
    ///   `profiles` — narrows precisely (e.g. "profile=asw AND inside this /24"), which is
    ///   what "взять только группу устройств" calls for. An *unset* dimension never
    ///   itself excludes a device (leaving `profiles` empty means "don't filter by
    ///   profile", not "matches nothing").
    /// - **A selector with zero populated dimensions at all (`subnets`, `profiles`, and
    ///   `device_ids` all empty) matches nothing, not everything.** This is a safety
    ///   default the user didn't explicitly dictate either way: the "AND across populated
    ///   dimensions" rule is vacuously "match everything" when there are zero dimensions
    ///   to AND over, which would let an accidentally-empty selector silently freeze the
    ///   *entire* fleet — exactly the failure mode a "select a precise group" feature
    ///   must not have a silent trapdoor into. An operator who genuinely wants to
    ///   suppress everything can still do so explicitly and visibly (e.g. one subnet
    ///   spanning the whole fleet), never by leaving every field blank.
    pub fn matches(&self, ip: &str, profile: Option<&str>, device_id: Uuid) -> bool {
        if self.device_ids.contains(&device_id) {
            return true;
        }

        let mut any_other_dimension_populated = false;

        if !self.subnets.is_empty() {
            any_other_dimension_populated = true;
            let in_any_subnet = match ip.parse::<std::net::Ipv4Addr>() {
                Ok(candidate) => self
                    .subnets
                    .iter()
                    .any(|s| ipv4_in_subnet(candidate, &s.ip, &s.mask).unwrap_or(false)),
                Err(_) => false, // unparseable ip — can't be inside any subnet
            };
            if !in_any_subnet {
                return false;
            }
        }

        if !self.profiles.is_empty() {
            any_other_dimension_populated = true;
            let matches_profile = profile.is_some_and(|p| self.profiles.iter().any(|w| w == p));
            if !matches_profile {
                return false;
            }
        }

        // Every populated dimension (if any) passed above — but if none were populated
        // at all, there's nothing this device could have matched against; see this
        // method's docs on why that reads as "matches nothing", not "matches everything".
        any_other_dimension_populated
    }
}

/// `true` if `device_id` (at `ip`, on profile `profile`) currently falls under any
/// `enabled` window in `windows` whose `[starts_at, ends_at]` contains `now`. The single
/// check `AlertEvalHandler` runs once per device per `AlertEval` tick — `windows` is
/// loaded once by the caller (batch-not-loop: not re-queried per rule, see that handler's
/// docs) — and `discovery-web` runs once per device per `GET /api/devices` page to
/// compute the "под ТО" indicator (also loaded once per request, not per device).
pub fn is_device_under_maintenance(
    windows: &[MaintenanceWindow],
    ip: &str,
    profile: Option<&str>,
    device_id: Uuid,
    now: DateTime<Utc>,
) -> bool {
    windows
        .iter()
        .any(|w| w.is_active(now) && w.matches(ip, profile, device_id))
}

/// Where the list of maintenance windows lives. One implementation —
/// [`SeaOrmMaintenanceWindowStore`], works against Postgres/MySQL/SQLite (and, for
/// tests/zero-config, `sqlite::memory:`) — same "one trait, one sea-orm implementation"
/// shape as [`crate::DiscoveryConfigStore`]/[`crate::SettingsStore`].
#[async_trait]
pub trait MaintenanceWindowStore: Send + Sync {
    async fn list_all(&self) -> anyhow::Result<Vec<MaintenanceWindow>>;

    /// Single-row lookup by id — `None` if no such window exists.
    async fn get(&self, id: Uuid) -> anyhow::Result<Option<MaintenanceWindow>>;

    /// Insert-or-replace-by-id — same "id decides create vs edit" contract
    /// `discovery_alerts::AlertStore::upsert` uses. A caller creating a brand-new window
    /// generates a fresh `Uuid::new_v4()` itself (`discovery-web`'s `POST` handler);
    /// passing an existing id edits that window in place.
    async fn upsert(&self, window: &MaintenanceWindow) -> anyhow::Result<()>;

    /// No-op (not an error) if `id` doesn't exist — same convention as
    /// `discovery_alerts::AlertStore::delete`.
    async fn delete(&self, id: Uuid) -> anyhow::Result<()>;
}

/// The sea-orm-backed implementation — see [`MaintenanceWindowStore`]'s docs.
pub struct SeaOrmMaintenanceWindowStore {
    db: sea_orm::DatabaseConnection,
}

impl SeaOrmMaintenanceWindowStore {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self { db }
    }

    /// Convenience for tests — same shape as every other sea-orm store's
    /// `new_in_memory_for_tests`.
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

fn model_to_window(
    m: discovery_entities::maintenance_windows::Model,
) -> anyhow::Result<MaintenanceWindow> {
    Ok(MaintenanceWindow {
        id: m.id,
        name: m.name,
        enabled: m.enabled,
        starts_at: m.starts_at,
        ends_at: m.ends_at,
        subnets: serde_json::from_value(m.subnets)?,
        profiles: serde_json::from_value(m.profiles)?,
        device_ids: serde_json::from_value(m.device_ids)?,
    })
}

#[async_trait]
impl MaintenanceWindowStore for SeaOrmMaintenanceWindowStore {
    async fn list_all(&self) -> anyhow::Result<Vec<MaintenanceWindow>> {
        use discovery_entities::maintenance_windows::Entity;
        use sea_orm::EntityTrait;
        Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(model_to_window)
            .collect()
    }

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<MaintenanceWindow>> {
        use discovery_entities::maintenance_windows::Entity;
        use sea_orm::EntityTrait;
        Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(model_to_window)
            .transpose()
    }

    async fn upsert(&self, window: &MaintenanceWindow) -> anyhow::Result<()> {
        use discovery_entities::maintenance_windows::{ActiveModel, Column, Entity};
        use sea_orm::sea_query::OnConflict;
        use sea_orm::{ActiveValue::Set, EntityTrait};

        let now = chrono::Utc::now();
        let am = ActiveModel {
            id: Set(window.id),
            name: Set(window.name.clone()),
            enabled: Set(window.enabled),
            starts_at: Set(window.starts_at),
            ends_at: Set(window.ends_at),
            subnets: Set(serde_json::to_value(&window.subnets)?),
            profiles: Set(serde_json::to_value(&window.profiles)?),
            device_ids: Set(serde_json::to_value(&window.device_ids)?),
            created_at: Set(now),
            updated_at: Set(now),
        };
        // `CreatedAt` deliberately excluded from `update_columns` — on a genuine insert
        // it's `now` (set above); on a conflict (an edit) the existing row's original
        // `created_at` is left untouched, only every other column gets overwritten.
        Entity::insert(am)
            .on_conflict(
                OnConflict::column(Column::Id)
                    .update_columns([
                        Column::Name,
                        Column::Enabled,
                        Column::StartsAt,
                        Column::EndsAt,
                        Column::Subnets,
                        Column::Profiles,
                        Column::DeviceIds,
                        Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        use discovery_entities::maintenance_windows::Entity;
        use sea_orm::EntityTrait;
        Entity::delete_by_id(id).exec(&self.db).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(
        subnets: Vec<SubnetTarget>,
        profiles: Vec<String>,
        device_ids: Vec<Uuid>,
    ) -> MaintenanceWindow {
        let now = Utc::now();
        MaintenanceWindow {
            id: Uuid::new_v4(),
            name: "test window".into(),
            enabled: true,
            starts_at: now - chrono::Duration::hours(1),
            ends_at: now + chrono::Duration::hours(1),
            subnets,
            profiles,
            device_ids,
        }
    }

    fn subnet(ip: &str, mask: &str) -> SubnetTarget {
        SubnetTarget {
            ip: ip.to_string(),
            mask: mask.to_string(),
        }
    }

    // ---- TASK-20260921-017: SubnetTarget::validate ----

    #[test]
    fn validate_accepts_a_well_formed_subnet() {
        assert!(subnet("10.0.0.0", "255.255.255.0").validate().is_ok());
        assert!(subnet("10.0.0.5", "255.255.255.0").validate().is_ok(), "host bits set is not rejected — see this method's docs on why normalization isn't needed");
        assert!(
            subnet("0.0.0.0", "0.0.0.0").validate().is_ok(),
            "the widest possible mask is still a valid contiguous mask"
        );
        assert!(
            subnet("10.0.0.5", "255.255.255.255").validate().is_ok(),
            "/32 single-host is valid"
        );
    }

    #[test]
    fn validate_rejects_a_malformed_ip() {
        let err = subnet("not-an-ip", "255.255.255.0").validate().unwrap_err();
        assert!(err.to_string().contains("not-an-ip"));
    }

    #[test]
    fn validate_rejects_a_non_contiguous_mask() {
        let err = subnet("10.0.0.0", "255.0.255.0").validate().unwrap_err();
        assert!(err.to_string().contains("255.0.255.0"));
    }

    #[test]
    fn validate_rejects_a_mask_that_is_not_an_ip_at_all() {
        assert!(subnet("10.0.0.0", "not-a-mask").validate().is_err());
    }

    // ---- selector matching: individual dimensions ----

    #[test]
    fn empty_selector_matches_nothing_not_everything() {
        let w = window(vec![], vec![], vec![]);
        assert!(
            !w.matches("10.0.0.5", Some("asw"), Uuid::new_v4()),
            "a completely empty selector must be a safety no-op, not a fleet-wide match"
        );
    }

    #[test]
    fn subnet_only_matches_inside_and_excludes_outside() {
        let w = window(vec![subnet("10.0.0.0", "255.255.255.0")], vec![], vec![]);
        assert!(w.matches("10.0.0.42", None, Uuid::new_v4()));
        assert!(
            !w.matches("10.0.1.42", None, Uuid::new_v4()),
            "outside the subnet must not match"
        );
    }

    #[test]
    fn subnet_dimension_matches_any_of_several_configured_subnets() {
        let w = window(
            vec![
                subnet("10.0.0.0", "255.255.255.0"),
                subnet("192.168.1.0", "255.255.255.0"),
            ],
            vec![],
            vec![],
        );
        assert!(w.matches("10.0.0.5", None, Uuid::new_v4()));
        assert!(w.matches("192.168.1.5", None, Uuid::new_v4()));
        assert!(!w.matches("172.16.0.5", None, Uuid::new_v4()));
    }

    #[test]
    fn profile_only_matches_exact_name_not_others() {
        let w = window(
            vec![],
            vec!["asw".to_string(), "olt_xpon".to_string()],
            vec![],
        );
        assert!(w.matches("10.0.0.5", Some("asw"), Uuid::new_v4()));
        assert!(w.matches("10.0.0.5", Some("olt_xpon"), Uuid::new_v4()));
        assert!(!w.matches("10.0.0.5", Some("switch_0"), Uuid::new_v4()));
        assert!(
            !w.matches("10.0.0.5", None, Uuid::new_v4()),
            "no profile on the device must not match a profile-scoped selector"
        );
    }

    // ---- AND across populated dimensions ----

    #[test]
    fn subnet_and_profile_both_populated_requires_both_to_hold() {
        let w = window(
            vec![subnet("10.0.0.0", "255.255.255.0")],
            vec!["asw".to_string()],
            vec![],
        );
        assert!(
            w.matches("10.0.0.5", Some("asw"), Uuid::new_v4()),
            "inside the subnet AND matching profile — must match"
        );
        assert!(
            !w.matches("10.0.0.5", Some("olt_xpon"), Uuid::new_v4()),
            "inside the subnet but wrong profile — must not match"
        );
        assert!(
            !w.matches("192.168.1.5", Some("asw"), Uuid::new_v4()),
            "matching profile but outside the subnet — must not match"
        );
    }

    // ---- device_ids: unconditional override ----

    #[test]
    fn device_id_matches_unconditionally_even_outside_every_other_dimension() {
        let target = Uuid::new_v4();
        let w = window(
            vec![subnet("10.0.0.0", "255.255.255.0")],
            vec!["asw".to_string()],
            vec![target],
        );
        // Wrong subnet, wrong profile — still matches because the id is explicitly listed.
        assert!(w.matches("192.168.1.5", Some("switch_0"), target));
        assert!(
            w.matches("192.168.1.5", None, target),
            "still matches even with no profile at all"
        );
    }

    #[test]
    fn device_id_populated_but_not_listed_falls_back_to_other_dimensions() {
        let listed = Uuid::new_v4();
        let other = Uuid::new_v4();
        let w = window(
            vec![subnet("10.0.0.0", "255.255.255.0")],
            vec![],
            vec![listed],
        );
        assert!(
            w.matches("10.0.0.5", None, other),
            "not in the allow-list, but still inside the populated subnet dimension"
        );
        assert!(
            !w.matches("192.168.1.5", None, other),
            "not in the allow-list and outside the only other populated dimension"
        );
    }

    #[test]
    fn device_ids_only_populated_excludes_devices_not_in_the_list() {
        let listed = Uuid::new_v4();
        let other = Uuid::new_v4();
        let w = window(vec![], vec![], vec![listed]);
        assert!(w.matches("10.0.0.5", Some("asw"), listed));
        assert!(
            !w.matches("10.0.0.5", Some("asw"), other),
            "device_ids is the only populated dimension — an unlisted device must not match"
        );
    }

    // ---- time-window boundary ----

    #[test]
    fn is_active_is_inclusive_at_both_boundaries() {
        let starts = Utc::now();
        let ends = starts + chrono::Duration::hours(2);
        let w = MaintenanceWindow {
            id: Uuid::new_v4(),
            name: "boundary".into(),
            enabled: true,
            starts_at: starts,
            ends_at: ends,
            subnets: vec![],
            profiles: vec![],
            device_ids: vec![],
        };
        assert!(
            w.is_active(starts),
            "exactly at starts_at must already be active"
        );
        assert!(w.is_active(ends), "exactly at ends_at must still be active");
        assert!(
            w.is_active(starts + chrono::Duration::minutes(1)),
            "strictly inside the window"
        );
        assert!(
            !w.is_active(starts - chrono::Duration::seconds(1)),
            "one second before starts_at must not be active"
        );
        assert!(
            !w.is_active(ends + chrono::Duration::seconds(1)),
            "one second after ends_at must not be active"
        );
    }

    #[test]
    fn disabled_window_is_never_active_regardless_of_time_range() {
        let now = Utc::now();
        let w = MaintenanceWindow {
            id: Uuid::new_v4(),
            name: "disabled".into(),
            enabled: false,
            starts_at: now - chrono::Duration::hours(1),
            ends_at: now + chrono::Duration::hours(1),
            subnets: vec![],
            profiles: vec![],
            device_ids: vec![],
        };
        assert!(
            !w.is_active(now),
            "enabled=false is an independent kill-switch, even squarely inside the time range"
        );
    }

    // ---- is_device_under_maintenance: aggregates multiple windows ----

    #[test]
    fn is_device_under_maintenance_true_if_any_window_matches_and_is_active() {
        let now = Utc::now();
        let device_id = Uuid::new_v4();
        let irrelevant = window(vec![subnet("192.168.1.0", "255.255.255.0")], vec![], vec![]);
        let matching = window(vec![subnet("10.0.0.0", "255.255.255.0")], vec![], vec![]);
        assert!(is_device_under_maintenance(
            &[irrelevant.clone(), matching],
            "10.0.0.5",
            None,
            device_id,
            now
        ));
        assert!(!is_device_under_maintenance(
            &[irrelevant],
            "10.0.0.5",
            None,
            device_id,
            now
        ));
    }

    #[test]
    fn is_device_under_maintenance_false_once_time_range_has_ended() {
        let device_id = Uuid::new_v4();
        let past = MaintenanceWindow {
            id: Uuid::new_v4(),
            name: "past".into(),
            enabled: true,
            starts_at: Utc::now() - chrono::Duration::hours(3),
            ends_at: Utc::now() - chrono::Duration::hours(1),
            subnets: vec![],
            profiles: vec![],
            device_ids: vec![device_id],
        };
        assert!(!is_device_under_maintenance(
            &[past],
            "10.0.0.5",
            None,
            device_id,
            Utc::now()
        ));
    }

    // ---- store CRUD round trip ----

    #[tokio::test]
    async fn store_round_trips_create_edit_and_delete() {
        let store = SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await;
        let device_id = Uuid::new_v4();
        let w = MaintenanceWindow {
            id: Uuid::new_v4(),
            name: "planned upgrade".into(),
            enabled: true,
            starts_at: Utc::now(),
            ends_at: Utc::now() + chrono::Duration::hours(2),
            subnets: vec![subnet("10.0.0.0", "255.255.255.0")],
            profiles: vec!["asw".to_string()],
            device_ids: vec![device_id],
        };
        store.upsert(&w).await.unwrap();

        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "planned upgrade");
        assert_eq!(all[0].subnets, vec![subnet("10.0.0.0", "255.255.255.0")]);
        assert_eq!(all[0].profiles, vec!["asw".to_string()]);
        assert_eq!(all[0].device_ids, vec![device_id]);

        let fetched = store.get(w.id).await.unwrap().expect("just inserted");
        assert_eq!(fetched.name, "planned upgrade");

        // Edit in place — same id, different fields; must update, not duplicate.
        let mut edited = w.clone();
        edited.name = "planned upgrade (extended)".into();
        edited.enabled = false;
        store.upsert(&edited).await.unwrap();
        let all = store.list_all().await.unwrap();
        assert_eq!(
            all.len(),
            1,
            "same id — must update in place, not create a second row"
        );
        assert_eq!(all[0].name, "planned upgrade (extended)");
        assert!(!all[0].enabled);

        store.delete(w.id).await.unwrap();
        assert!(store.list_all().await.unwrap().is_empty());

        // Deleting a nonexistent id is a no-op, not an error — same convention as
        // `discovery_alerts::AlertStore::delete`.
        store.delete(Uuid::new_v4()).await.unwrap();
    }

    #[tokio::test]
    async fn get_returns_none_for_an_unknown_id() {
        let store = SeaOrmMaintenanceWindowStore::new_in_memory_for_tests().await;
        assert!(store.get(Uuid::new_v4()).await.unwrap().is_none());
    }
}
