//! Derived topology data: which key each device presents under a
//! `discovery_config_store::TopologyRule` (`topology_device_keys`), and which neighbor
//! keys it claims to see (`topology_claims`) — plus turning that raw per-device data into
//! resolved device-to-device pairs.
//!
//! **The core design point, from the discussion that produced this crate**: a claim is
//! only ever written by the device that made it (`apply_recompute` touches exactly one
//! device's own rows), never mirrored onto the other side. Visibility from *both* sides
//! of an edge comes entirely from how [`resolve_edges`] reads the data back — "who do I
//! claim" joined against "who claims my own key" — not from any write fanning out to a
//! second device. This is what makes the reactive recompute genuinely cheap: recomputing
//! device B after its own metric changes never requires re-touching device A, yet A sees
//! the new edge to B the very next time anything reads the graph.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    sea_query::OnConflict, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter, TransactionTrait,
};
use serde::Serialize;
use uuid::Uuid;

/// One resolved neighbor of a specific device, from that device's point of view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedNeighbor {
    pub neighbor_device_id: Uuid,
    /// Both sides claim each other (`resolve_edges`'s docs) — the higher-confidence case.
    /// `false` means only one side currently does; still a real edge, just not (yet, or
    /// no longer) mutually confirmed — see this crate's module docs on why that's an
    /// expected, non-alarming steady state, not a data-quality bug.
    pub confirmed: bool,
    /// Which device is upstream on this edge — `None` if undetermined (no manual override,
    /// and either side lacks a rank or both ranks tie). See [`apply_hierarchy`].
    pub upstream_device_id: Option<Uuid>,
    /// `true` if `upstream_device_id` came from a manual `topology_hierarchy_overrides` row
    /// rather than from comparing `topology_device_keys.rank`.
    pub direction_overridden: bool,
}

/// One resolved edge in the whole fleet-wide graph for a rule — same `confirmed` meaning
/// as [`ResolvedNeighbor`]. `device_a < device_b` always (canonical ordering — an edge is
/// undirected; which side happened to claim it first is not meaningful, see this crate's
/// module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedEdge {
    pub device_a: Uuid,
    pub device_b: Uuid,
    pub confirmed: bool,
    /// Which of `device_a`/`device_b` is upstream — `None` if undetermined. Always one of
    /// the two device ids when `Some`, never a third device. Populated by [`apply_hierarchy`]
    /// as a second pass over `resolve_edges`'s output — `resolve_edges` itself only ever
    /// produces `None`/`false` here, it knows nothing about rank or overrides.
    pub upstream_device_id: Option<Uuid>,
    pub direction_overridden: bool,
}

/// Joins raw per-device `my_key`s against raw claims into resolved, deduplicated,
/// canonically-ordered edges — pure and DB-free so it's unit-testable on its own (no
/// sqlite round trip needed to exercise the actual matching logic). `device_keys` and
/// `claims` are both scoped to one rule already; this function doesn't know or care about
/// `rule_name`.
///
/// O(devices + claims) — one hash-map build over `device_keys`, one pass over `claims`,
/// never a comparison of every device against every other device. See
/// `.claude/rules/engineering-patterns.md`'s "батч вместо цикла на hot path": this
/// generalizes the same chassis-id-hash-index approach an LLDP-only implementation would
/// use, just keyed by whatever string a rule's `my_key_expression` produces instead of a
/// protocol-specific field.
pub fn resolve_edges(
    device_keys: &[(Uuid, String)],
    claims: &[(Uuid, String)],
) -> Vec<ResolvedEdge> {
    let by_key: HashMap<&str, Uuid> = device_keys
        .iter()
        .map(|(id, key)| (key.as_str(), *id))
        .collect();

    // (lo, hi) -> (does lo claim hi?, does hi claim lo?)
    let mut pairs: HashMap<(Uuid, Uuid), (bool, bool)> = HashMap::new();
    for (claimer, claimed_key) in claims {
        // A neighbor key nobody currently presents as their own `my_key` resolves to
        // nothing — the claiming device's own data is fine, the *neighbor* just hasn't
        // registered yet (or never will: unmanaged gear, a rule mismatch, etc.). Dropped,
        // not fabricated into a dangling edge — same posture the LLDP design discussion
        // settled on.
        let Some(&neighbor) = by_key.get(claimed_key.as_str()) else {
            continue;
        };
        if *claimer == neighbor {
            continue; // self-claim — duplicated device/misconfigured rule, not an edge
        }
        let (lo, hi) = if *claimer < neighbor {
            (*claimer, neighbor)
        } else {
            (neighbor, *claimer)
        };
        let entry = pairs.entry((lo, hi)).or_insert((false, false));
        if *claimer == lo {
            entry.0 = true;
        } else {
            entry.1 = true;
        }
    }

    let mut edges: Vec<ResolvedEdge> = pairs
        .into_iter()
        .map(|((a, b), (lo_claims_hi, hi_claims_lo))| ResolvedEdge {
            device_a: a,
            device_b: b,
            confirmed: lo_claims_hi && hi_claims_lo,
            upstream_device_id: None,
            direction_overridden: false,
        })
        .collect();
    edges.sort_by_key(|e| (e.device_a, e.device_b));
    edges
}

/// Second pass over [`resolve_edges`]'s output — fills in `upstream_device_id`/
/// `direction_overridden`, leaving adjacency (`confirmed`) completely untouched. Pure and
/// DB-free, same "unit-testable without a sqlite round trip" shape as `resolve_edges`.
///
/// Precedence per edge: a manual override (`overrides`, keyed by the same canonical
/// `(min, max)` pair `resolve_edges` already produces) wins outright when present; else the
/// side with the strictly lower `ranks` value wins; else `None` — a tie, or either side
/// missing a rank, is left undetermined rather than fabricated. `ranks`/`overrides` are
/// fleet-wide for one rule, same scope `device_keys`/`claims` already have in
/// `resolve_edges`.
pub fn apply_hierarchy(
    edges: Vec<ResolvedEdge>,
    ranks: &HashMap<Uuid, f64>,
    overrides: &HashMap<(Uuid, Uuid), Uuid>,
) -> Vec<ResolvedEdge> {
    edges
        .into_iter()
        .map(|mut edge| {
            if let Some(&upstream) = overrides.get(&(edge.device_a, edge.device_b)) {
                edge.upstream_device_id = Some(upstream);
                edge.direction_overridden = true;
                return edge;
            }
            if let (Some(&rank_a), Some(&rank_b)) =
                (ranks.get(&edge.device_a), ranks.get(&edge.device_b))
            {
                if rank_a < rank_b {
                    edge.upstream_device_id = Some(edge.device_a);
                } else if rank_b < rank_a {
                    edge.upstream_device_id = Some(edge.device_b);
                }
                // Equal ranks: leave `None` — a tie is not a determined direction.
            }
            edge
        })
        .collect()
}

/// Projects the whole-fleet edge list down to one device's neighbors — deliberately built
/// on top of [`resolve_edges`] rather than a separate query path, so `neighbors_of` and
/// `resolved_edges` can never disagree with each other about what counts as an edge.
pub fn neighbors_from_edges(device_id: Uuid, edges: &[ResolvedEdge]) -> Vec<ResolvedNeighbor> {
    edges
        .iter()
        .filter_map(|e| {
            if e.device_a == device_id {
                Some(ResolvedNeighbor {
                    neighbor_device_id: e.device_b,
                    confirmed: e.confirmed,
                    upstream_device_id: e.upstream_device_id,
                    direction_overridden: e.direction_overridden,
                })
            } else if e.device_b == device_id {
                Some(ResolvedNeighbor {
                    neighbor_device_id: e.device_a,
                    confirmed: e.confirmed,
                    upstream_device_id: e.upstream_device_id,
                    direction_overridden: e.direction_overridden,
                })
            } else {
                None
            }
        })
        .collect()
}

#[async_trait]
pub trait TopologyStore: Send + Sync {
    /// Atomically replaces device `device_id`'s state under rule `rule_name`: its own
    /// `my_key` (upserted, or deleted if `my_key` is `None` — it no longer participates in
    /// this rule) and every claim it makes (old claims deleted, `claimed_keys` inserted
    /// fresh). One transaction — a concurrent read must never observe the old claims
    /// deleted but the new ones not yet inserted, same "several tables, one transaction"
    /// shape `DeviceStore::record_metric_polls` already uses for
    /// `device_metrics`+`device_metric_history`.
    /// `rank` is this device's `rank_expression` result under this rule — `None` if the
    /// rule has no rank expression, or it evaluated to `()`/non-numeric for this device
    /// (`discovery_dsl::topology::TopologyEvaluator::evaluate_rank`). Stored in the same
    /// row/transaction as `my_key`, so it's cleared automatically along with the whole row
    /// when `my_key` is `None` — no separate cleanup needed.
    async fn apply_recompute(
        &self,
        rule_name: &str,
        device_id: Uuid,
        my_key: Option<String>,
        claimed_keys: Vec<String>,
        rank: Option<f64>,
    ) -> anyhow::Result<()>;

    /// This device's resolved neighbors under one rule — see [`neighbors_from_edges`]'s
    /// docs. Returns an empty list (not an error) for a device that isn't registered
    /// under this rule at all.
    async fn neighbors_of(
        &self,
        rule_name: &str,
        device_id: Uuid,
    ) -> anyhow::Result<Vec<ResolvedNeighbor>>;

    /// The whole resolved graph for one rule — what the topology dashboard page renders.
    async fn resolved_edges(&self, rule_name: &str) -> anyhow::Result<Vec<ResolvedEdge>>;

    /// Manually pins the upstream side of the edge between `device_a`/`device_b` under one
    /// rule — overriding whatever `apply_hierarchy` would otherwise compute from rank alone
    /// (a tie, a missing rank, or just a customer without disciplined enough role/profile
    /// data for the automatic signal). Canonicalizes `(device_a, device_b)` to `(min, max)`
    /// itself, same convention `resolve_edges` uses. `upstream_device_id` must equal
    /// `device_a` or `device_b` — validated here (a hard `Err` otherwise) since nothing in
    /// the schema enforces it (this project has no `CHECK` constraints anywhere,
    /// cross-backend); the REST layer validates too for immediate feedback, but this is the
    /// actual persistence boundary. Setting an override for a pair with no edge yet under
    /// this rule is not an error — same "claim on an unregistered key is dropped, not
    /// fabricated" tolerance `resolve_edges` already has; `apply_hierarchy` simply won't
    /// find a matching edge to apply it to until one exists.
    async fn set_hierarchy_override(
        &self,
        rule_name: &str,
        device_a: Uuid,
        device_b: Uuid,
        upstream_device_id: Uuid,
    ) -> anyhow::Result<()>;

    /// No-op (not an error) if no override exists for this pair under this rule.
    async fn clear_hierarchy_override(
        &self,
        rule_name: &str,
        device_a: Uuid,
        device_b: Uuid,
    ) -> anyhow::Result<()>;

    /// Removes every cached key, claim, and hierarchy override for one rule.
    /// Used when a rule is renamed, disabled, or deleted so its old graph cannot
    /// remain visible until another metric poll happens.
    async fn delete_for_rule(&self, rule_name: &str) -> anyhow::Result<()>;

    /// Removes every trace of `device_id` across *every* rule — its own key, its claims,
    /// and any hierarchy override it's a side of — called from `DeviceStore::delete`, the
    /// same explicit cross-domain cleanup call
    /// `AlertStore::delete_for_device`/`DeviceMetricsStore::delete_for_device` already are
    /// (Devices and Topology can be routed to different physical databases, so there's no
    /// DB-level `ON DELETE CASCADE` to rely on here).
    async fn delete_for_device(&self, device_id: Uuid) -> anyhow::Result<()>;
}

pub struct SeaOrmTopologyStore {
    db: DatabaseConnection,
}

impl SeaOrmTopologyStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }

    /// One row per (rule, device): `(device_id, my_key, rank)` — rank rides along with
    /// `my_key` in the same query, since both live on the same `topology_device_keys` row;
    /// no separate table/read needed just because hierarchy is a newer concept than
    /// adjacency.
    async fn load_device_keys(
        &self,
        rule_name: &str,
    ) -> anyhow::Result<Vec<(Uuid, String, Option<f64>)>> {
        use discovery_entities::topology_device_keys::{Column, Entity};
        Ok(Entity::find()
            .filter(Column::RuleName.eq(rule_name))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| (m.device_id, m.my_key, m.rank))
            .collect())
    }

    async fn load_claims(&self, rule_name: &str) -> anyhow::Result<Vec<(Uuid, String)>> {
        use discovery_entities::topology_claims::{Column, Entity};
        Ok(Entity::find()
            .filter(Column::RuleName.eq(rule_name))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| (m.claimer_device_id, m.claimed_key))
            .collect())
    }

    async fn load_overrides(&self, rule_name: &str) -> anyhow::Result<HashMap<(Uuid, Uuid), Uuid>> {
        use discovery_entities::topology_hierarchy_overrides::{Column, Entity};
        Ok(Entity::find()
            .filter(Column::RuleName.eq(rule_name))
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| ((m.device_a, m.device_b), m.upstream_device_id))
            .collect())
    }

    /// Resolves the full graph for one rule, hierarchy included — shared by `neighbors_of`
    /// and `resolved_edges` so the two views can never disagree about direction any more
    /// than they already can't disagree about adjacency (`neighbors_from_edges` is built on
    /// `resolve_edges`'s output the same way).
    async fn resolve(&self, rule_name: &str) -> anyhow::Result<Vec<ResolvedEdge>> {
        let device_keys = self.load_device_keys(rule_name).await?;
        let claims = self.load_claims(rule_name).await?;
        let overrides = self.load_overrides(rule_name).await?;

        let keys_for_join: Vec<(Uuid, String)> = device_keys
            .iter()
            .map(|(id, key, _)| (*id, key.clone()))
            .collect();
        let ranks: HashMap<Uuid, f64> = device_keys
            .into_iter()
            .filter_map(|(id, _, rank)| rank.map(|r| (id, r)))
            .collect();

        let edges = resolve_edges(&keys_for_join, &claims);
        Ok(apply_hierarchy(edges, &ranks, &overrides))
    }
}

#[async_trait]
impl TopologyStore for SeaOrmTopologyStore {
    async fn apply_recompute(
        &self,
        rule_name: &str,
        device_id: Uuid,
        my_key: Option<String>,
        claimed_keys: Vec<String>,
        rank: Option<f64>,
    ) -> anyhow::Result<()> {
        use discovery_entities::topology_claims::{
            ActiveModel as ClaimActiveModel, Column as ClaimColumn, Entity as ClaimEntity,
        };
        use discovery_entities::topology_device_keys::{
            ActiveModel as KeyActiveModel, Column as KeyColumn, Entity as KeyEntity,
        };

        let txn = self.db.begin().await?;
        let now = Utc::now();

        match &my_key {
            Some(key) => {
                let am = KeyActiveModel {
                    rule_name: Set(rule_name.to_string()),
                    device_id: Set(device_id),
                    my_key: Set(key.clone()),
                    rank: Set(rank),
                    updated_at: Set(now),
                };
                KeyEntity::insert(am)
                    .on_conflict(
                        OnConflict::columns([KeyColumn::RuleName, KeyColumn::DeviceId])
                            .update_columns([
                                KeyColumn::MyKey,
                                KeyColumn::Rank,
                                KeyColumn::UpdatedAt,
                            ])
                            .to_owned(),
                    )
                    .exec(&txn)
                    .await?;
            }
            None => {
                KeyEntity::delete_many()
                    .filter(KeyColumn::RuleName.eq(rule_name))
                    .filter(KeyColumn::DeviceId.eq(device_id))
                    .exec(&txn)
                    .await?;
            }
        }

        // Replace-all-for-(rule, device): delete every existing claim this device made
        // under this rule, then insert the fresh set. A device that now claims nothing
        // (`claimed_keys` empty, or `my_key` is `None`) ends up with zero claim rows,
        // exactly like it never had any — not a leftover stale row.
        ClaimEntity::delete_many()
            .filter(ClaimColumn::RuleName.eq(rule_name))
            .filter(ClaimColumn::ClaimerDeviceId.eq(device_id))
            .exec(&txn)
            .await?;
        if my_key.is_some() && !claimed_keys.is_empty() {
            let models: Vec<ClaimActiveModel> = claimed_keys
                .into_iter()
                .map(|claimed_key| ClaimActiveModel {
                    rule_name: Set(rule_name.to_string()),
                    claimer_device_id: Set(device_id),
                    claimed_key: Set(claimed_key),
                    observed_at: Set(now),
                })
                .collect();
            ClaimEntity::insert_many(models).exec(&txn).await?;
        }

        txn.commit().await?;
        Ok(())
    }

    async fn neighbors_of(
        &self,
        rule_name: &str,
        device_id: Uuid,
    ) -> anyhow::Result<Vec<ResolvedNeighbor>> {
        let edges = self.resolve(rule_name).await?;
        Ok(neighbors_from_edges(device_id, &edges))
    }

    async fn resolved_edges(&self, rule_name: &str) -> anyhow::Result<Vec<ResolvedEdge>> {
        self.resolve(rule_name).await
    }

    async fn set_hierarchy_override(
        &self,
        rule_name: &str,
        device_a: Uuid,
        device_b: Uuid,
        upstream_device_id: Uuid,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            upstream_device_id == device_a || upstream_device_id == device_b,
            "upstream_device_id must be one of the two devices in the edge"
        );
        use discovery_entities::topology_hierarchy_overrides::{ActiveModel, Column, Entity};

        let (lo, hi) = if device_a < device_b {
            (device_a, device_b)
        } else {
            (device_b, device_a)
        };
        let am = ActiveModel {
            rule_name: Set(rule_name.to_string()),
            device_a: Set(lo),
            device_b: Set(hi),
            upstream_device_id: Set(upstream_device_id),
            updated_at: Set(Utc::now()),
        };
        Entity::insert(am)
            .on_conflict(
                OnConflict::columns([Column::RuleName, Column::DeviceA, Column::DeviceB])
                    .update_columns([Column::UpstreamDeviceId, Column::UpdatedAt])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn clear_hierarchy_override(
        &self,
        rule_name: &str,
        device_a: Uuid,
        device_b: Uuid,
    ) -> anyhow::Result<()> {
        use discovery_entities::topology_hierarchy_overrides::{Column, Entity};

        let (lo, hi) = if device_a < device_b {
            (device_a, device_b)
        } else {
            (device_b, device_a)
        };
        Entity::delete_many()
            .filter(Column::RuleName.eq(rule_name))
            .filter(Column::DeviceA.eq(lo))
            .filter(Column::DeviceB.eq(hi))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn delete_for_device(&self, device_id: Uuid) -> anyhow::Result<()> {
        use discovery_entities::topology_claims::{Column as ClaimColumn, Entity as ClaimEntity};
        use discovery_entities::topology_device_keys::{Column as KeyColumn, Entity as KeyEntity};
        use discovery_entities::topology_hierarchy_overrides::{
            Column as OverrideColumn, Entity as OverrideEntity,
        };
        use sea_orm::Condition;

        let txn = self.db.begin().await?;
        KeyEntity::delete_many()
            .filter(KeyColumn::DeviceId.eq(device_id))
            .exec(&txn)
            .await?;
        ClaimEntity::delete_many()
            .filter(ClaimColumn::ClaimerDeviceId.eq(device_id))
            .exec(&txn)
            .await?;
        // `upstream_device_id` is never set to anything other than `device_a`/`device_b`
        // (`set_hierarchy_override`'s own invariant), so filtering on those two columns
        // covers it too — no separate `UpstreamDeviceId` clause needed.
        OverrideEntity::delete_many()
            .filter(
                Condition::any()
                    .add(OverrideColumn::DeviceA.eq(device_id))
                    .add(OverrideColumn::DeviceB.eq(device_id)),
            )
            .exec(&txn)
            .await?;
        txn.commit().await?;
        Ok(())
    }

    async fn delete_for_rule(&self, rule_name: &str) -> anyhow::Result<()> {
        use discovery_entities::topology_claims::{Column as ClaimColumn, Entity as ClaimEntity};
        use discovery_entities::topology_device_keys::{Column as KeyColumn, Entity as KeyEntity};
        use discovery_entities::topology_hierarchy_overrides::{
            Column as OverrideColumn, Entity as OverrideEntity,
        };

        let txn = self.db.begin().await?;
        KeyEntity::delete_many()
            .filter(KeyColumn::RuleName.eq(rule_name))
            .exec(&txn)
            .await?;
        ClaimEntity::delete_many()
            .filter(ClaimColumn::RuleName.eq(rule_name))
            .exec(&txn)
            .await?;
        OverrideEntity::delete_many()
            .filter(OverrideColumn::RuleName.eq(rule_name))
            .exec(&txn)
            .await?;
        txn.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    // ---- pure resolution logic, no DB ----

    #[test]
    fn two_devices_that_claim_each_other_resolve_to_one_confirmed_edge() {
        let a = id(1);
        let b = id(2);
        let device_keys = vec![(a, "key-a".to_string()), (b, "key-b".to_string())];
        let claims = vec![(a, "key-b".to_string()), (b, "key-a".to_string())];

        let edges = resolve_edges(&device_keys, &claims);
        assert_eq!(edges.len(), 1);
        assert!(edges[0].confirmed);
        assert_eq!(
            (
                edges[0].device_a.min(edges[0].device_b),
                edges[0].device_a.max(edges[0].device_b)
            ),
            (a.min(b), a.max(b))
        );
    }

    /// The exact scenario from the design discussion: device A polls first and claims B —
    /// B hasn't registered its own key yet, so nothing resolves. Then B polls (registers
    /// its own key + claims A) — **A is never touched again**, yet A's claim now resolves,
    /// because resolution happens at read time against whatever's currently in
    /// `device_keys`, not at the moment A itself was written.
    #[test]
    fn a_claim_resolves_once_the_target_registers_its_own_key_without_reprocessing_the_claimer() {
        let a = id(1);
        let b = id(2);

        // Tick 1: only A has polled so far.
        let device_keys_tick1 = vec![(a, "key-a".to_string())];
        let claims_tick1 = vec![(a, "key-b".to_string())]; // A claims B, but B isn't registered yet
        assert!(
            resolve_edges(&device_keys_tick1, &claims_tick1).is_empty(),
            "B hasn't registered its own key yet — nothing to resolve to"
        );

        // Tick 2: B has now polled and registered itself (A's row is untouched — same
        // `claims_tick1` list, just with B's key added to `device_keys`).
        let device_keys_tick2 = vec![(a, "key-a".to_string()), (b, "key-b".to_string())];
        let edges = resolve_edges(&device_keys_tick2, &claims_tick1);
        assert_eq!(
            edges.len(),
            1,
            "A's original claim now resolves purely because B registered — A was never re-touched"
        );
        assert!(
            !edges[0].confirmed,
            "only A claims B so far — B hasn't claimed A back"
        );
        assert_eq!(
            neighbors_from_edges(a, &edges),
            vec![ResolvedNeighbor {
                neighbor_device_id: b,
                confirmed: false,
                upstream_device_id: None,
                direction_overridden: false
            }]
        );
        assert_eq!(
            neighbors_from_edges(b, &edges),
            vec![ResolvedNeighbor {
                neighbor_device_id: a,
                confirmed: false,
                upstream_device_id: None,
                direction_overridden: false
            }]
        );
    }

    #[test]
    fn a_claim_pointing_at_an_unregistered_key_is_dropped_not_fabricated() {
        let a = id(1);
        let device_keys = vec![(a, "key-a".to_string())];
        let claims = vec![(a, "key-nonexistent".to_string())];
        assert!(resolve_edges(&device_keys, &claims).is_empty());
    }

    #[test]
    fn a_device_claiming_its_own_key_is_not_an_edge() {
        let a = id(1);
        let device_keys = vec![(a, "key-a".to_string())];
        let claims = vec![(a, "key-a".to_string())];
        assert!(resolve_edges(&device_keys, &claims).is_empty());
    }

    #[test]
    fn asymmetric_drift_after_a_recompute_is_not_an_error_edge_just_stays_unconfirmed() {
        let a = id(1);
        let b = id(2);
        let device_keys = vec![(a, "key-a".to_string()), (b, "key-b".to_string())];
        // Only A claims B now (B's own claim to A "naturally" dropped off on B's last
        // recompute) — direct scenario from the design discussion ("это не страшно, это
        // естественные убытки").
        let claims = vec![(a, "key-b".to_string())];
        let edges = resolve_edges(&device_keys, &claims);
        assert_eq!(edges.len(), 1);
        assert!(!edges[0].confirmed);
    }

    // ---- apply_hierarchy, pure, no DB ----

    fn confirmed_edge(a: Uuid, b: Uuid) -> ResolvedEdge {
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        ResolvedEdge {
            device_a: lo,
            device_b: hi,
            confirmed: true,
            upstream_device_id: None,
            direction_overridden: false,
        }
    }

    #[test]
    fn lower_rank_wins_as_upstream() {
        let a = id(1);
        let b = id(2);
        let ranks = HashMap::from([(a, 0.0), (b, 1.0)]);
        let edges = apply_hierarchy(vec![confirmed_edge(a, b)], &ranks, &HashMap::new());
        assert_eq!(edges[0].upstream_device_id, Some(a));
        assert!(!edges[0].direction_overridden);
    }

    #[test]
    fn a_rank_tie_leaves_direction_undetermined() {
        let a = id(1);
        let b = id(2);
        let ranks = HashMap::from([(a, 1.0), (b, 1.0)]);
        let edges = apply_hierarchy(vec![confirmed_edge(a, b)], &ranks, &HashMap::new());
        assert_eq!(edges[0].upstream_device_id, None);
    }

    #[test]
    fn a_missing_rank_on_either_side_leaves_direction_undetermined() {
        let a = id(1);
        let b = id(2);
        let ranks = HashMap::from([(a, 0.0)]); // b has no rank at all
        let edges = apply_hierarchy(vec![confirmed_edge(a, b)], &ranks, &HashMap::new());
        assert_eq!(edges[0].upstream_device_id, None);
    }

    #[test]
    fn an_override_wins_even_when_rank_disagrees() {
        let a = id(1);
        let b = id(2);
        let ranks = HashMap::from([(a, 0.0), (b, 1.0)]); // rank alone would say `a` is upstream
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let overrides = HashMap::from([((lo, hi), b)]);
        let edges = apply_hierarchy(vec![confirmed_edge(a, b)], &ranks, &overrides);
        assert_eq!(edges[0].upstream_device_id, Some(b));
        assert!(edges[0].direction_overridden);
    }

    #[test]
    fn an_override_for_a_pair_with_no_edge_is_simply_never_applied() {
        let a = id(1);
        let b = id(2);
        let c = id(3);
        let (lo, hi) = if a < c { (a, c) } else { (c, a) };
        let overrides = HashMap::from([((lo, hi), a)]); // a/c override, but only a/b has an edge
        let edges = apply_hierarchy(vec![confirmed_edge(a, b)], &HashMap::new(), &overrides);
        assert_eq!(edges[0].upstream_device_id, None);
    }

    // ---- SeaOrm-backed store, sqlite :memory: ----

    #[tokio::test]
    async fn apply_recompute_then_neighbors_of_round_trips_through_real_storage() {
        use discovery_config_store_test_support::*;

        let store = SeaOrmTopologyStore::new_in_memory_for_tests().await;
        insert_rule(&store.db, "lldp").await;

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-b".to_string()],
                None,
            )
            .await
            .unwrap();
        assert!(
            store.neighbors_of("lldp", a).await.unwrap().is_empty(),
            "B hasn't registered yet"
        );

        store
            .apply_recompute(
                "lldp",
                b,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                None,
            )
            .await
            .unwrap();
        let neighbors_a = store.neighbors_of("lldp", a).await.unwrap();
        assert_eq!(
            neighbors_a,
            vec![ResolvedNeighbor {
                neighbor_device_id: b,
                confirmed: true,
                upstream_device_id: None,
                direction_overridden: false
            }]
        );
        let neighbors_b = store.neighbors_of("lldp", b).await.unwrap();
        assert_eq!(
            neighbors_b,
            vec![ResolvedNeighbor {
                neighbor_device_id: a,
                confirmed: true,
                upstream_device_id: None,
                direction_overridden: false
            }]
        );

        let edges = store.resolved_edges("lldp").await.unwrap();
        assert_eq!(edges.len(), 1);
        assert!(edges[0].confirmed);
    }

    #[tokio::test]
    async fn apply_recompute_replaces_old_claims_atomically() {
        use discovery_config_store_test_support::*;

        let store = SeaOrmTopologyStore::new_in_memory_for_tests().await;
        insert_rule(&store.db, "lldp").await;

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        store
            .apply_recompute("lldp", b, Some("key-b".to_string()), vec![], None)
            .await
            .unwrap();
        store
            .apply_recompute("lldp", c, Some("key-c".to_string()), vec![], None)
            .await
            .unwrap();
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-b".to_string()],
                None,
            )
            .await
            .unwrap();
        assert_eq!(store.neighbors_of("lldp", a).await.unwrap().len(), 1);

        // A's port moved — now points at C instead of B. Old claim to B must be gone, not
        // just appended to.
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-c".to_string()],
                None,
            )
            .await
            .unwrap();
        let neighbors_a = store.neighbors_of("lldp", a).await.unwrap();
        assert_eq!(
            neighbors_a,
            vec![ResolvedNeighbor {
                neighbor_device_id: c,
                confirmed: false,
                upstream_device_id: None,
                direction_overridden: false
            }]
        );
    }

    #[tokio::test]
    async fn my_key_none_clears_this_devices_key_and_claims_under_the_rule() {
        use discovery_config_store_test_support::*;

        let store = SeaOrmTopologyStore::new_in_memory_for_tests().await;
        insert_rule(&store.db, "lldp").await;

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        store
            .apply_recompute(
                "lldp",
                b,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                None,
            )
            .await
            .unwrap();
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-b".to_string()],
                None,
            )
            .await
            .unwrap();
        assert_eq!(store.neighbors_of("lldp", b).await.unwrap().len(), 1);

        // A's profile changed — it no longer polls the metric this rule needs.
        store
            .apply_recompute("lldp", a, None, vec![], None)
            .await
            .unwrap();
        assert!(
            store.neighbors_of("lldp", b).await.unwrap().is_empty(),
            "A withdrew its own key — B's claim to it can no longer resolve"
        );
        assert!(store.resolved_edges("lldp").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_for_device_removes_its_keys_and_claims_across_every_rule() {
        use discovery_config_store_test_support::*;

        let store = SeaOrmTopologyStore::new_in_memory_for_tests().await;
        insert_rule(&store.db, "lldp").await;
        insert_rule(&store.db, "fdb").await;

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-b".to_string()],
                None,
            )
            .await
            .unwrap();
        store
            .apply_recompute(
                "lldp",
                b,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                None,
            )
            .await
            .unwrap();
        store
            .apply_recompute(
                "fdb",
                a,
                Some("mac-a".to_string()),
                vec!["mac-b".to_string()],
                None,
            )
            .await
            .unwrap();

        store.delete_for_device(a).await.unwrap();
        assert!(store.neighbors_of("lldp", b).await.unwrap().is_empty());
        assert!(store.resolved_edges("fdb").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rank_persists_alongside_my_key_and_resolves_direction_on_both_views() {
        use discovery_config_store_test_support::*;

        let store = SeaOrmTopologyStore::new_in_memory_for_tests().await;
        insert_rule(&store.db, "lldp").await;

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-b".to_string()],
                Some(0.0),
            )
            .await
            .unwrap();
        store
            .apply_recompute(
                "lldp",
                b,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                Some(1.0),
            )
            .await
            .unwrap();

        let edges = store.resolved_edges("lldp").await.unwrap();
        assert_eq!(
            edges[0].upstream_device_id,
            Some(a),
            "lower rank must resolve as upstream"
        );

        let neighbors_a = store.neighbors_of("lldp", a).await.unwrap();
        let neighbors_b = store.neighbors_of("lldp", b).await.unwrap();
        assert_eq!(
            neighbors_a[0].upstream_device_id,
            Some(a),
            "both sides' views must agree on direction"
        );
        assert_eq!(neighbors_b[0].upstream_device_id, Some(a));
    }

    #[tokio::test]
    async fn rank_is_cleared_along_with_my_key_when_a_device_withdraws_from_a_rule() {
        use discovery_config_store_test_support::*;

        let store = SeaOrmTopologyStore::new_in_memory_for_tests().await;
        insert_rule(&store.db, "lldp").await;

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-b".to_string()],
                Some(0.0),
            )
            .await
            .unwrap();
        store
            .apply_recompute(
                "lldp",
                b,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                Some(1.0),
            )
            .await
            .unwrap();
        assert_eq!(
            store.resolved_edges("lldp").await.unwrap()[0].upstream_device_id,
            Some(a)
        );

        // A's profile changed — this rule's rank_expression's metric is no longer polled.
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-b".to_string()],
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            store.resolved_edges("lldp").await.unwrap()[0].upstream_device_id,
            None,
            "rank withdrawn — direction is undetermined again, not stale"
        );
    }

    #[tokio::test]
    async fn hierarchy_override_wins_over_rank_and_can_be_cleared() {
        use discovery_config_store_test_support::*;

        let store = SeaOrmTopologyStore::new_in_memory_for_tests().await;
        insert_rule(&store.db, "lldp").await;

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-b".to_string()],
                Some(0.0),
            )
            .await
            .unwrap();
        store
            .apply_recompute(
                "lldp",
                b,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                Some(1.0),
            )
            .await
            .unwrap();
        assert_eq!(
            store.resolved_edges("lldp").await.unwrap()[0].upstream_device_id,
            Some(a),
            "rank alone says a is upstream"
        );

        // Override says the opposite — passed in the "wrong" a/b order to also prove
        // canonicalization happens inside the store, not just in the caller.
        store.set_hierarchy_override("lldp", b, a, b).await.unwrap();
        let edges = store.resolved_edges("lldp").await.unwrap();
        assert_eq!(edges[0].upstream_device_id, Some(b));
        assert!(edges[0].direction_overridden);

        store.clear_hierarchy_override("lldp", a, b).await.unwrap();
        let edges = store.resolved_edges("lldp").await.unwrap();
        assert_eq!(
            edges[0].upstream_device_id,
            Some(a),
            "clearing the override falls back to rank again"
        );
        assert!(!edges[0].direction_overridden);

        // No-op, not an error, same convention as `TopologyRuleStore::delete` on an
        // unknown id.
        store.clear_hierarchy_override("lldp", a, b).await.unwrap();
    }

    #[tokio::test]
    async fn set_hierarchy_override_rejects_an_upstream_not_in_the_pair() {
        let store = SeaOrmTopologyStore::new_in_memory_for_tests().await;
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        assert!(store.set_hierarchy_override("lldp", a, b, c).await.is_err());
    }

    #[tokio::test]
    async fn delete_for_device_also_removes_hierarchy_overrides_it_is_a_side_of() {
        use discovery_config_store_test_support::*;

        let store = SeaOrmTopologyStore::new_in_memory_for_tests().await;
        insert_rule(&store.db, "lldp").await;

        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a".to_string()),
                vec!["key-b".to_string()],
                None,
            )
            .await
            .unwrap();
        store
            .apply_recompute(
                "lldp",
                b,
                Some("key-b".to_string()),
                vec!["key-a".to_string()],
                None,
            )
            .await
            .unwrap();
        store.set_hierarchy_override("lldp", a, b, a).await.unwrap();

        store.delete_for_device(a).await.unwrap();
        assert!(
            store.resolved_edges("lldp").await.unwrap().is_empty(),
            "a's key is gone — no edge left at all"
        );

        // Re-register the same `a`/`b` ids (a device_id is stable across a real device's
        // lifetime; this simulates the same physical device being re-onboarded) without
        // ever re-setting an override. If the override row had leaked as an orphan instead
        // of being purged by `delete_for_device`, it would silently reapply here.
        store
            .apply_recompute(
                "lldp",
                a,
                Some("key-a-2".to_string()),
                vec!["key-b-2".to_string()],
                None,
            )
            .await
            .unwrap();
        store
            .apply_recompute(
                "lldp",
                b,
                Some("key-b-2".to_string()),
                vec!["key-a-2".to_string()],
                None,
            )
            .await
            .unwrap();
        let edges = store.resolved_edges("lldp").await.unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(
            edges[0].upstream_device_id, None,
            "the old override must not have survived device deletion"
        );
    }

    /// Minimal helper to satisfy `topology_rules`'s `ON DELETE CASCADE` FK target without
    /// pulling in a dependency on `discovery-config-store` (that crate already depends on
    /// nothing here, and adding the reverse edge just for test fixtures isn't worth a new
    /// workspace dependency edge) — inserts a bare row directly via the entity this crate
    /// already depends on transitively through `discovery-entities`.
    mod discovery_config_store_test_support {
        use sea_orm::{ActiveValue::Set, DatabaseConnection, EntityTrait};

        pub async fn insert_rule(db: &DatabaseConnection, name: &str) {
            use discovery_entities::topology_rules::ActiveModel;
            let now = chrono::Utc::now();
            let am = ActiveModel {
                id: Set(uuid::Uuid::new_v4()),
                name: Set(name.to_string()),
                enabled: Set(true),
                my_key_expression: Set("metrics.key".to_string()),
                claimed_neighbors_expression: Set(None),
                rank_expression: Set(None),
                watched_metrics: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };
            discovery_entities::topology_rules::Entity::insert(am)
                .exec(db)
                .await
                .unwrap();
        }
    }
}
