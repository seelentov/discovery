use std::collections::HashMap;

use async_trait::async_trait;
use chrono::Utc;
use discovery_core::{
    Alert, AlertComment, AlertCommentAttachment, AlertLevel, AlertState, AutoClearReason,
    NewAttachment, SortDir,
};
use discovery_entities::alert_comment_attachments::{
    ActiveModel as AttachmentActiveModel, Column as AttachmentColumn, Entity as AttachmentEntity,
    Model as AttachmentModel,
};
use discovery_entities::alert_comments::{
    ActiveModel as CommentActiveModel, Column as CommentColumn, Entity as CommentEntity,
    Model as CommentModel,
};
use discovery_entities::alerts::{ActiveModel, Column, Entity, Model};
use sea_orm::sea_query::{Expr, Func, OnConflict};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, DatabaseConnection, EntityTrait,
    FromQueryResult, Order, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect,
};
use uuid::Uuid;

use crate::{AlertListPage, AlertListQuery, AlertSortBy, AlertStore};

fn level_to_str(level: AlertLevel) -> &'static str {
    match level {
        AlertLevel::Info => "info",
        AlertLevel::Warning => "warning",
        AlertLevel::Critical => "critical",
    }
}

fn level_from_str(s: &str) -> AlertLevel {
    match s {
        "critical" => AlertLevel::Critical,
        "warning" => AlertLevel::Warning,
        _ => AlertLevel::Info,
    }
}

fn state_to_str(state: &AlertState) -> &'static str {
    match state {
        AlertState::Active => "active",
        AlertState::Cleared => "cleared",
    }
}

fn state_from_str(s: &str) -> AlertState {
    match s {
        "cleared" => AlertState::Cleared,
        _ => AlertState::Active,
    }
}

fn auto_clear_reason_to_str(reason: AutoClearReason) -> &'static str {
    match reason {
        AutoClearReason::RowMissing => "row_missing",
    }
}

fn auto_clear_reason_from_str(s: &str) -> Option<AutoClearReason> {
    match s {
        "row_missing" => Some(AutoClearReason::RowMissing),
        _ => None,
    }
}

fn sort_column(sort_by: AlertSortBy) -> Column {
    match sort_by {
        AlertSortBy::FirstSeen => Column::FirstSeen,
        AlertSortBy::LastSeen => Column::LastSeen,
        AlertSortBy::Level => Column::Level,
        AlertSortBy::Name => Column::Name,
        AlertSortBy::DeviceIp => Column::DeviceIp,
    }
}

fn model_to_alert(m: Model, comment_count: i64) -> Alert {
    Alert {
        details: m
            .details
            .map(serde_json::from_value)
            .transpose()
            .unwrap_or_default()
            .unwrap_or_default(),
        id: m.id,
        device_id: m.device_id,
        device_ip: m.device_ip,
        name: m.name,
        row_key: m.row_key,
        level: level_from_str(&m.level),
        message: m.message,
        state: state_from_str(&m.state),
        facts: m.facts,
        first_seen: m.first_seen,
        last_seen: m.last_seen,
        cleared_at: m.cleared_at,
        closed_by: m.closed_by,
        acknowledged_by: m.acknowledged_by,
        acknowledged_at: m.acknowledged_at,
        snoozed_until: m.snoozed_until,
        snoozed_by: m.snoozed_by,
        auto_clear_reason: m
            .auto_clear_reason
            .as_deref()
            .and_then(auto_clear_reason_from_str),
        flapping: m.flapping,
        suppression_reason: m.suppression_reason,
        comment_count,
        suppressed_by_alert_id: m.suppressed_by_alert_id,
        reopened_from_alert_id: m.reopened_from_alert_id,
        repeat_count: m.repeat_count.max(0) as u32,
        escalation_level: m.escalation_level.max(0) as u32,
        repeated_at: m.repeated_at,
        escalation_reason: m.escalation_reason,
    }
}

fn comment_model_to_comment(
    m: CommentModel,
    attachments: Vec<AlertCommentAttachment>,
) -> AlertComment {
    AlertComment {
        id: m.id,
        alert_id: m.alert_id,
        author: m.author,
        created_at: m.created_at,
        text: m.text,
        attachments,
    }
}

fn attachment_model_to_meta(m: &AttachmentModel) -> AlertCommentAttachment {
    AlertCommentAttachment {
        id: m.id,
        comment_id: m.comment_id,
        filename: m.filename.clone(),
        content_type: m.content_type.clone(),
        size: m.size,
    }
}

/// Metadata-only projection of `alert_comment_attachments` — deliberately excludes
/// `data` so a bulk `list_comments` fetch never pulls attachment bytes into memory just
/// to discard them (see [`AlertCommentAttachment`]'s docs on why the split exists).
#[derive(FromQueryResult)]
struct AttachmentMetaRow {
    id: Uuid,
    comment_id: Uuid,
    filename: String,
    content_type: String,
    size: i64,
}

fn attachment_meta_row_to_meta(r: AttachmentMetaRow) -> AlertCommentAttachment {
    AlertCommentAttachment {
        id: r.id,
        comment_id: r.comment_id,
        filename: r.filename,
        content_type: r.content_type,
        size: r.size,
    }
}

/// The sea-orm-backed implementation, replacing the old `PostgresAlertStore`/
/// `SqliteAlertStore`/`InMemoryAlertStore` trio (2026-08-18, same multi-DB rewrite as
/// `discovery_config_store::SeaOrmSettingsStore` — see that struct's docs for the full
/// rationale). Alerts are rows in `alerts` (`discovery_entities::alerts`,
/// `crates/migration`) — `device_id` is a **soft** reference, no enforced `FOREIGN KEY`
/// (see that entity's docs: "Тревоги" and "Устройства" can resolve to different physical
/// databases once per-domain routing is configured).
pub struct SeaOrmAlertStore {
    db: DatabaseConnection,
}

impl SeaOrmAlertStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Convenience for tests across the workspace — see `SeaOrmSettingsStore::new_in_memory_for_tests`'s
    /// docs for why this exists and why it's async, unlike the old `InMemoryAlertStore::new()`.
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }

    /// One batched `GROUP BY` for exactly the alert ids being returned (bounded by
    /// `AlertListQuery::limit`, never the full candidate set) — not a per-row `COUNT`
    /// query, same "resolve names/counts once per request" discipline
    /// `discovery-web::build_device_views`'s `profiles_by_name` map uses.
    async fn comment_counts(&self, alert_ids: &[Uuid]) -> anyhow::Result<HashMap<Uuid, i64>> {
        if alert_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, i64)> = CommentEntity::find()
            .filter(CommentColumn::AlertId.is_in(alert_ids.to_vec()))
            .select_only()
            .column(CommentColumn::AlertId)
            .column_as(CommentColumn::Id.count(), "cnt")
            .group_by(CommentColumn::AlertId)
            .into_tuple()
            .all(&self.db)
            .await?;
        Ok(rows.into_iter().collect())
    }
}

#[async_trait]
impl AlertStore for SeaOrmAlertStore {
    async fn save_runtime(
        &self,
        device_id: Uuid,
        snapshot: &discovery_core::AlertRuntimeSnapshot,
    ) -> anyhow::Result<()> {
        use discovery_entities::alert_runtime::{ActiveModel as Runtime, Column as C, Entity as E};
        E::insert(Runtime {
            device_id: Set(device_id),
            snapshot: Set(serde_json::to_value(snapshot)?),
        })
        .on_conflict(
            OnConflict::column(C::DeviceId)
                .update_column(C::Snapshot)
                .to_owned(),
        )
        .exec(&self.db)
        .await?;
        Ok(())
    }
    async fn runtime_page(
        &self,
        limit: u32,
        offset: u64,
    ) -> anyhow::Result<Vec<discovery_core::DeviceAlertRuntime>> {
        use discovery_entities::alert_runtime::{Column as C, Entity as E};
        E::find()
            .order_by_asc(C::DeviceId)
            .limit(u64::from(limit.min(500)))
            .offset(offset)
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| {
                Ok(discovery_core::DeviceAlertRuntime {
                    device_id: m.device_id,
                    snapshot: serde_json::from_value(m.snapshot)?,
                })
            })
            .collect()
    }
    async fn shared_rules(
        &self,
    ) -> anyhow::Result<std::collections::BTreeMap<String, serde_json::Value>> {
        Ok(discovery_entities::alert_rule_definitions::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| (m.name, m.definition))
            .collect())
    }
    async fn save_shared_rule(
        &self,
        name: &str,
        definition: serde_json::Value,
    ) -> anyhow::Result<()> {
        use discovery_entities::alert_rule_definitions::{
            ActiveModel as Rule, Column as C, Entity as E,
        };
        E::insert(Rule {
            name: Set(name.into()),
            definition: Set(definition),
        })
        .on_conflict(
            OnConflict::column(C::Name)
                .update_column(C::Definition)
                .to_owned(),
        )
        .exec(&self.db)
        .await?;
        Ok(())
    }
    async fn delete_shared_rule(&self, name: &str) -> anyhow::Result<()> {
        discovery_entities::alert_rule_definitions::Entity::delete_by_id(name.to_string())
            .exec(&self.db)
            .await?;
        Ok(())
    }
    async fn record_source_event(
        &self,
        event: &discovery_core::AlertSourceEvent,
    ) -> anyhow::Result<()> {
        use discovery_entities::alert_source_events::{ActiveModel as Source, Entity as E};
        E::insert(Source {
            id: Set(event.id),
            device_id: Set(event.device_id),
            metric: Set(event.metric.clone()),
            received_at: Set(event.received_at),
            data: Set(event.data.clone()),
        })
        .on_conflict(
            OnConflict::column(discovery_entities::alert_source_events::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .do_nothing()
        .exec(&self.db)
        .await?;
        Ok(())
    }
    async fn prune_source_events(&self, before: chrono::DateTime<Utc>) -> anyhow::Result<u64> {
        use discovery_entities::alert_source_events::{Column as C, Entity as E};
        Ok(E::delete_many()
            .filter(C::ReceivedAt.lt(before.fixed_offset()))
            .exec(&self.db)
            .await?
            .rows_affected)
    }
    async fn source_events(
        &self,
        device_id: Uuid,
        since: chrono::DateTime<Utc>,
    ) -> anyhow::Result<Vec<discovery_core::AlertSourceEvent>> {
        use discovery_entities::alert_source_events::{Column as C, Entity as E};
        Ok(E::find()
            .filter(C::DeviceId.eq(device_id))
            .filter(C::ReceivedAt.gte(since))
            .order_by_asc(C::ReceivedAt)
            .order_by_asc(C::Id)
            .limit(10001)
            .all(&self.db)
            .await?
            .into_iter()
            .map(|m| discovery_core::AlertSourceEvent {
                id: m.id,
                device_id: m.device_id,
                metric: m.metric,
                received_at: m.received_at,
                data: m.data,
            })
            .collect())
    }

    async fn upsert(&self, alert: &Alert) -> anyhow::Result<()> {
        let am = ActiveModel {
            details: Set(Some(serde_json::to_value(&alert.details)?)),
            response_required: Set(alert.details.policy.acknowledge_required),
            response_escalated: Set(alert.details.response_escalated),
            screen_notification: Set(alert.details.policy.screen_notification),
            id: Set(alert.id),
            device_id: Set(alert.device_id),
            device_ip: Set(alert.device_ip.clone()),
            name: Set(alert.name.clone()),
            row_key: Set(alert.row_key.clone()),
            level: Set(level_to_str(alert.level).to_string()),
            message: Set(alert.message.clone()),
            state: Set(state_to_str(&alert.state).to_string()),
            facts: Set(alert.facts.clone()),
            first_seen: Set(alert.first_seen),
            last_seen: Set(alert.last_seen),
            cleared_at: Set(alert.cleared_at),
            closed_by: Set(alert.closed_by.clone()),
            acknowledged_by: Set(alert.acknowledged_by.clone()),
            acknowledged_at: Set(alert.acknowledged_at),
            snoozed_until: Set(alert.snoozed_until),
            snoozed_by: Set(alert.snoozed_by.clone()),
            auto_clear_reason: Set(alert
                .auto_clear_reason
                .map(auto_clear_reason_to_str)
                .map(str::to_string)),
            flapping: Set(alert.flapping),
            suppression_reason: Set(alert.suppression_reason.clone()),
            suppressed_by_alert_id: Set(alert.suppressed_by_alert_id),
            reopened_from_alert_id: Set(alert.reopened_from_alert_id),
            repeat_count: Set(alert.repeat_count as i32),
            escalation_level: Set(alert.escalation_level as i32),
            repeated_at: Set(alert.repeated_at),
            escalation_reason: Set(alert.escalation_reason.clone()),
        };
        Entity::insert(am)
            .on_conflict(
                OnConflict::column(Column::Id)
                    // `row_key`/`reopened_from_alert_id` deliberately absent — both frozen
                    // at insert, same "identity never changes across an incident's
                    // lifetime" contract `facts` already has (see
                    // `Alert::reopened_from_alert_id`'s docs — set once, at the initial
                    // `Activated` persist, never touched again).
                    .update_columns([
                        Column::Message,
                        Column::Details,
                        Column::ResponseRequired,
                        Column::ResponseEscalated,
                        Column::ScreenNotification,
                        Column::State,
                        Column::LastSeen,
                        Column::ClearedAt,
                        Column::ClosedBy,
                        Column::AutoClearReason,
                        Column::Flapping,
                        Column::SuppressionReason,
                        // Deliberately absent — see `AlertStore::set_suppression`'s docs.
                        // This column has its own dedicated write path now; including it
                        // here let a stale in-memory `AlertStateTracker` copy clobber
                        // whatever the group-alert sweep had just written.
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn set_suppression(
        &self,
        alert_id: Uuid,
        suppressed_by_alert_id: Option<Uuid>,
    ) -> anyhow::Result<()> {
        Entity::update_many()
            .col_expr(
                Column::SuppressedByAlertId,
                Expr::value(suppressed_by_alert_id),
            )
            .filter(Column::Id.eq(alert_id))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn set_acknowledgement(
        &self,
        alert_id: Uuid,
        acknowledged_by: Option<String>,
        acknowledged_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<()> {
        Entity::update_many()
            .col_expr(Column::AcknowledgedBy, Expr::value(acknowledged_by))
            .col_expr(Column::AcknowledgedAt, Expr::value(acknowledged_at))
            .filter(Column::Id.eq(alert_id))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn set_snooze(
        &self,
        alert_id: Uuid,
        snoozed_until: Option<chrono::DateTime<chrono::Utc>>,
        snoozed_by: Option<String>,
    ) -> anyhow::Result<()> {
        Entity::update_many()
            .col_expr(Column::SnoozedUntil, Expr::value(snoozed_until))
            .col_expr(Column::SnoozedBy, Expr::value(snoozed_by))
            .filter(Column::Id.eq(alert_id))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn find_recent_manual_close(
        &self,
        device_id: Uuid,
        name: &str,
        row_key: Option<&str>,
        since: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<Option<Alert>> {
        let mut cond = Condition::all()
            .add(Column::DeviceId.eq(device_id))
            .add(Column::Name.eq(name))
            .add(Column::State.eq(state_to_str(&AlertState::Cleared)))
            .add(Column::ClosedBy.is_not_null())
            .add(Column::ClearedAt.gte(since));
        cond = cond.add(match row_key {
            Some(k) => Column::RowKey.eq(k),
            None => Column::RowKey.is_null(),
        });
        let model = Entity::find()
            .filter(cond)
            .order_by_desc(Column::ClearedAt)
            .one(&self.db)
            .await?;
        // `comment_count: 0` — this `Alert` is only ever read for its `id` by the caller,
        // never rendered, so paying for the real count (a whole extra query) isn't worth it.
        Ok(model.map(|m| model_to_alert(m, 0)))
    }

    async fn list(&self, query: &AlertListQuery) -> anyhow::Result<AlertListPage> {
        let mut cond = Condition::all();
        if query.response_pending {
            cond = cond.add(
                Condition::any()
                    .add(
                        Condition::all()
                            .add(Column::ResponseRequired.eq(true))
                            .add(Column::AcknowledgedAt.is_null()),
                    )
                    .add(Column::ResponseEscalated.eq(true)),
            );
        }
        if query.screen_only {
            cond = cond
                .add(Column::ScreenNotification.eq(true))
                .add(Column::AcknowledgedAt.is_null())
                .add(
                    Condition::any()
                        .add(Column::State.eq("active"))
                        .add(Column::ResponseRequired.eq(true)),
                );
        }
        if let Some(search) = query.search.as_deref() {
            // `LOWER(col) LIKE %needle%` — portable case-insensitive search across all
            // three backends (the old hand-written Postgres backend used `ILIKE`
            // specifically because plain `LIKE` there *is* case-sensitive, unlike SQLite's
            // and MySQL's default collations — `LOWER()` on both sides sidesteps the
            // dialect difference entirely instead of branching per backend).
            let needle = format!("%{}%", search.to_lowercase());
            cond = cond.add(
                Condition::any()
                    .add(Expr::expr(Func::lower(Expr::col(Column::DeviceIp))).like(needle.clone()))
                    .add(Expr::expr(Func::lower(Expr::col(Column::Name))).like(needle.clone()))
                    .add(Expr::expr(Func::lower(Expr::col(Column::Message))).like(needle.clone()))
                    // Row-scoped alerts (2026-08-29) — lets "Gi0/3" find the right port
                    // even if the rule's own message text doesn't happen to embed it.
                    // `LOWER(NULL)` is `NULL`, `NULL LIKE ...` is unknown/false, so a
                    // device-level alert (`row_key IS NULL`) is simply never matched by
                    // this arm — no special-casing needed for it.
                    .add(Expr::expr(Func::lower(Expr::col(Column::RowKey))).like(needle)),
            );
        }
        if let Some(level) = query.level {
            cond = cond.add(Column::Level.eq(level_to_str(level)));
        }
        if let Some(state) = &query.state {
            cond = cond.add(Column::State.eq(state_to_str(state)));
        }
        if let Some(device_id) = query.device_id {
            cond = cond.add(Column::DeviceId.eq(device_id));
        }
        if let Some(since) = query.since {
            cond = cond.add(Column::FirstSeen.gte(since));
        }
        if let Some(until) = query.until {
            cond = cond.add(Column::FirstSeen.lte(until));
        }

        let total = Entity::find().filter(cond.clone()).count(&self.db).await? as i64;

        let order = if query.sort_dir == SortDir::Asc {
            Order::Asc
        } else {
            Order::Desc
        };
        let models = Entity::find()
            .filter(cond)
            .order_by(sort_column(query.sort_by), order)
            .order_by(Column::Id, Order::Asc) // stable tiebreaker, same as every other list() in this project
            .limit(query.limit.max(0) as u64)
            .offset(query.offset.max(0) as u64)
            .all(&self.db)
            .await?;

        let ids: Vec<Uuid> = models.iter().map(|m| m.id).collect();
        let counts = self.comment_counts(&ids).await?;
        let items = models
            .into_iter()
            .map(|m| {
                let count = *counts.get(&m.id).unwrap_or(&0);
                model_to_alert(m, count)
            })
            .collect();
        Ok(AlertListPage { items, total })
    }

    async fn get(&self, id: Uuid) -> anyhow::Result<Option<Alert>> {
        let Some(model) = Entity::find_by_id(id).one(&self.db).await? else {
            return Ok(None);
        };
        let counts = self.comment_counts(&[id]).await?;
        Ok(Some(model_to_alert(model, *counts.get(&id).unwrap_or(&0))))
    }

    async fn prune_cleared_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<u64> {
        // `cleared_at < cutoff` is `NULL < cutoff` (= unknown = excluded) for every active
        // alert, since `cleared_at` is only ever set on clear — no extra `state = 'active'`
        // exemption needed beyond the explicit state filter already here.
        let result = Entity::delete_many()
            .filter(Column::State.eq(state_to_str(&AlertState::Cleared)))
            .filter(Column::ClearedAt.lt(cutoff))
            .filter(
                Condition::any()
                    .add(Column::ResponseRequired.eq(false))
                    .add(Column::AcknowledgedAt.is_not_null()),
            )
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    async fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        Entity::delete_by_id(id).exec(&self.db).await?;
        Ok(())
    }

    async fn add_comment(
        &self,
        alert_id: Uuid,
        author: &str,
        text: &str,
        attachments: Vec<NewAttachment>,
    ) -> anyhow::Result<AlertComment> {
        if Entity::find_by_id(alert_id).one(&self.db).await?.is_none() {
            anyhow::bail!("no such alert '{alert_id}'");
        }
        let am = CommentActiveModel {
            id: Set(Uuid::new_v4()),
            alert_id: Set(alert_id),
            author: Set(author.to_string()),
            created_at: Set(Utc::now()),
            text: Set(text.to_string()),
        };
        let comment_model = am.insert(&self.db).await?;

        let mut meta = Vec::with_capacity(attachments.len());
        for a in attachments {
            let am = AttachmentActiveModel {
                id: Set(Uuid::new_v4()),
                comment_id: Set(comment_model.id),
                filename: Set(a.filename),
                content_type: Set(a.content_type),
                size: Set(a.data.len() as i64),
                data: Set(a.data),
            };
            meta.push(attachment_model_to_meta(&am.insert(&self.db).await?));
        }

        Ok(comment_model_to_comment(comment_model, meta))
    }

    async fn list_comments(&self, alert_id: Uuid) -> anyhow::Result<Vec<AlertComment>> {
        let rows = CommentEntity::find()
            .filter(CommentColumn::AlertId.eq(alert_id))
            .order_by_asc(CommentColumn::CreatedAt)
            .all(&self.db)
            .await?;

        let comment_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        let attachment_rows = AttachmentEntity::find()
            .filter(AttachmentColumn::CommentId.is_in(comment_ids))
            .select_only()
            .column(AttachmentColumn::Id)
            .column(AttachmentColumn::CommentId)
            .column(AttachmentColumn::Filename)
            .column(AttachmentColumn::ContentType)
            .column(AttachmentColumn::Size)
            .into_model::<AttachmentMetaRow>()
            .all(&self.db)
            .await?;
        let mut by_comment: HashMap<Uuid, Vec<AlertCommentAttachment>> = HashMap::new();
        for r in attachment_rows {
            by_comment
                .entry(r.comment_id)
                .or_default()
                .push(attachment_meta_row_to_meta(r));
        }

        Ok(rows
            .into_iter()
            .map(|m| {
                let attachments = by_comment.remove(&m.id).unwrap_or_default();
                comment_model_to_comment(m, attachments)
            })
            .collect())
    }

    async fn get_attachment(
        &self,
        attachment_id: Uuid,
    ) -> anyhow::Result<Option<(AlertCommentAttachment, Vec<u8>)>> {
        let Some(m) = AttachmentEntity::find_by_id(attachment_id)
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };
        let meta = attachment_model_to_meta(&m);
        Ok(Some((meta, m.data)))
    }

    async fn delete_for_device(&self, device_id: Uuid) -> anyhow::Result<u64> {
        discovery_entities::alert_runtime::Entity::delete_by_id(device_id)
            .exec(&self.db)
            .await?;
        discovery_entities::alert_source_events::Entity::delete_many()
            .filter(discovery_entities::alert_source_events::Column::DeviceId.eq(device_id))
            .exec(&self.db)
            .await?;
        let result = Entity::delete_many()
            .filter(Column::DeviceId.eq(device_id))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }

    async fn active_counts_by_device(
        &self,
        device_ids: &[Uuid],
    ) -> anyhow::Result<HashMap<Uuid, i64>> {
        if device_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, i64)> = Entity::find()
            .filter(Column::DeviceId.is_in(device_ids.to_vec()))
            .filter(Column::State.eq(state_to_str(&AlertState::Active)))
            .select_only()
            .column(Column::DeviceId)
            .column_as(Column::Id.count(), "cnt")
            .group_by(Column::DeviceId)
            .into_tuple()
            .all(&self.db)
            .await?;
        Ok(rows.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::AlertLevel;

    fn alert(id: Uuid, device_ip: &str, name: &str, state: AlertState, level: AlertLevel) -> Alert {
        let now = chrono::Utc::now();
        Alert {
            details: Default::default(),
            id,
            device_id: Uuid::new_v4(),
            device_ip: device_ip.to_string(),
            name: name.to_string(),
            row_key: None,
            level,
            message: format!("{name} on {device_ip}"),
            state: state.clone(),
            facts: Some(serde_json::json!({"ip": device_ip, "value": 42})),
            first_seen: now,
            last_seen: now,
            cleared_at: if state == AlertState::Cleared {
                Some(now)
            } else {
                None
            },
            closed_by: None,
            acknowledged_by: None,
            acknowledged_at: None,
            snoozed_until: None,
            snoozed_by: None,
            auto_clear_reason: None,
            repeat_count: 0,
            escalation_level: 0,
            repeated_at: None,
            escalation_reason: None,
            flapping: false,
            suppression_reason: None,
            comment_count: 0,
            suppressed_by_alert_id: None,
            reopened_from_alert_id: None,
        }
    }

    /// 2026-09-17 audit finding #4 — `find_recent_manual_close` is what
    /// `discovery_agent::handlers::persist_alert_transition` calls to decide
    /// `Alert::reopened_from_alert_id`. Covers the three ways a candidate must be excluded
    /// (wrong key, auto-cleared not manual, outside the window) alongside the one way it
    /// must match.
    #[tokio::test]
    async fn find_recent_manual_close_matches_only_a_manually_closed_same_key_alert_within_the_window(
    ) {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let device_id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let mut manual_match = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "high_cpu",
            AlertState::Cleared,
            AlertLevel::Warning,
        );
        manual_match.device_id = device_id;
        manual_match.closed_by = Some("noc-operator".to_string());
        manual_match.cleared_at = Some(now - chrono::Duration::minutes(2));
        store.upsert(&manual_match).await.unwrap();

        // Different name — must not match.
        let mut wrong_name = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "port_down",
            AlertState::Cleared,
            AlertLevel::Warning,
        );
        wrong_name.device_id = device_id;
        wrong_name.closed_by = Some("noc-operator".to_string());
        wrong_name.cleared_at = Some(now - chrono::Duration::minutes(2));
        store.upsert(&wrong_name).await.unwrap();

        // Auto-cleared (no closed_by) — must not match, even same key and recent.
        let mut auto_cleared = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "high_cpu",
            AlertState::Cleared,
            AlertLevel::Warning,
        );
        auto_cleared.device_id = device_id;
        auto_cleared.closed_by = None;
        auto_cleared.cleared_at = Some(now - chrono::Duration::seconds(30));
        store.upsert(&auto_cleared).await.unwrap();

        // Manually closed but outside the window — must not match.
        let mut too_old = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "high_cpu",
            AlertState::Cleared,
            AlertLevel::Warning,
        );
        too_old.device_id = device_id;
        too_old.closed_by = Some("noc-operator".to_string());
        too_old.cleared_at = Some(now - chrono::Duration::hours(2));
        store.upsert(&too_old).await.unwrap();

        let since = now - chrono::Duration::minutes(10);
        let found = store
            .find_recent_manual_close(device_id, "high_cpu", None, since)
            .await
            .unwrap();
        assert_eq!(found.map(|a| a.id), Some(manual_match.id), "must find exactly the manually closed same-key alert inside the window, none of the three distractors");

        // No matching alert at all for an unrelated device.
        let none_found = store
            .find_recent_manual_close(Uuid::new_v4(), "high_cpu", None, since)
            .await
            .unwrap();
        assert!(none_found.is_none());
    }

    #[tokio::test]
    async fn upsert_is_insert_or_update_by_id_and_facts_json_round_trips() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let id = Uuid::new_v4();
        store
            .upsert(&alert(
                id,
                "10.0.0.1",
                "high_cpu",
                AlertState::Active,
                AlertLevel::Warning,
            ))
            .await
            .unwrap();

        let fetched = store.get(id).await.unwrap().unwrap();
        assert_eq!(
            fetched.facts,
            Some(serde_json::json!({"ip": "10.0.0.1", "value": 42}))
        );

        let mut updated = alert(
            id,
            "10.0.0.1",
            "high_cpu",
            AlertState::Cleared,
            AlertLevel::Warning,
        );
        updated.message = "resolved".into();
        store.upsert(&updated).await.unwrap();

        let page = store.list(&AlertListQuery::default()).await.unwrap();
        assert_eq!(
            page.total, 1,
            "same id must update in place, not create a second row"
        );
        assert_eq!(page.items[0].message, "resolved");
        assert_eq!(page.items[0].state, AlertState::Cleared);
    }

    /// Direct user request 2026-08-29 ("тревога по порту"): `row_key` and
    /// `auto_clear_reason` must round-trip through the DB — `row_key` frozen from
    /// activation (never in `on_conflict`'s update list, same treatment as `facts`),
    /// `auto_clear_reason` only appearing once the alert actually clears with a reason.
    #[tokio::test]
    async fn row_key_and_auto_clear_reason_round_trip() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let id = Uuid::new_v4();
        let mut a = alert(
            id,
            "10.0.0.1",
            "port_down",
            AlertState::Active,
            AlertLevel::Warning,
        );
        a.row_key = Some("Gi0/3".to_string());
        store.upsert(&a).await.unwrap();

        let fetched = store.get(id).await.unwrap().unwrap();
        assert_eq!(fetched.row_key.as_deref(), Some("Gi0/3"));
        assert_eq!(fetched.auto_clear_reason, None);

        let mut cleared = fetched;
        cleared.state = AlertState::Cleared;
        cleared.cleared_at = Some(chrono::Utc::now());
        cleared.auto_clear_reason = Some(AutoClearReason::RowMissing);
        store.upsert(&cleared).await.unwrap();

        let refetched = store.get(id).await.unwrap().unwrap();
        assert_eq!(
            refetched.row_key.as_deref(),
            Some("Gi0/3"),
            "row_key must survive the update, frozen from activation"
        );
        assert_eq!(
            refetched.auto_clear_reason,
            Some(AutoClearReason::RowMissing)
        );
    }

    #[tokio::test]
    async fn search_matches_row_key_too() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let mut a = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "port_down",
            AlertState::Active,
            AlertLevel::Warning,
        );
        a.row_key = Some("Gi0/3".to_string());
        store.upsert(&a).await.unwrap();

        let page = store
            .list(&AlertListQuery {
                search: Some("gi0/3".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            page.total, 1,
            "search must match row_key case-insensitively, same as device_ip/name/message"
        );
    }

    #[tokio::test]
    async fn search_matches_ip_name_and_message_case_insensitively() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        store
            .upsert(&alert(
                Uuid::new_v4(),
                "10.0.0.1",
                "high_cpu",
                AlertState::Active,
                AlertLevel::Warning,
            ))
            .await
            .unwrap();
        store
            .upsert(&alert(
                Uuid::new_v4(),
                "10.0.0.2",
                "low_disk",
                AlertState::Active,
                AlertLevel::Critical,
            ))
            .await
            .unwrap();

        let by_ip = store
            .list(&AlertListQuery {
                search: Some("10.0.0.1".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_ip.total, 1);

        let by_name = store
            .list(&AlertListQuery {
                search: Some("LOW_DISK".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_name.total, 1);
        assert_eq!(by_name.items[0].device_ip, "10.0.0.2");
    }

    #[tokio::test]
    async fn filters_by_level_state_and_device_id() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let a = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "a",
            AlertState::Active,
            AlertLevel::Warning,
        );
        let b = alert(
            Uuid::new_v4(),
            "10.0.0.2",
            "b",
            AlertState::Cleared,
            AlertLevel::Critical,
        );
        store.upsert(&a).await.unwrap();
        store.upsert(&b).await.unwrap();

        let warnings = store
            .list(&AlertListQuery {
                level: Some(AlertLevel::Warning),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(warnings.total, 1);

        let active = store
            .list(&AlertListQuery {
                state: Some(AlertState::Active),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(active.total, 1);
        assert_eq!(active.items[0].name, "a");

        let by_device = store
            .list(&AlertListQuery {
                device_id: Some(a.device_id),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_device.total, 1);
        assert_eq!(by_device.items[0].id, a.id);
    }

    #[tokio::test]
    async fn sort_and_pagination() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        for ip in ["10.0.0.3", "10.0.0.1", "10.0.0.2"] {
            store
                .upsert(&alert(
                    Uuid::new_v4(),
                    ip,
                    "x",
                    AlertState::Active,
                    AlertLevel::Info,
                ))
                .await
                .unwrap();
        }

        let page = store
            .list(&AlertListQuery {
                sort_by: AlertSortBy::DeviceIp,
                sort_dir: SortDir::Asc,
                limit: 2,
                offset: 0,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            page.total, 3,
            "total must reflect all matches, not just this page"
        );
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].device_ip, "10.0.0.1");
        assert_eq!(page.items[1].device_ip, "10.0.0.2");
    }

    #[tokio::test]
    async fn prune_cleared_older_than_leaves_active_alerts_and_recent_cleared_ones_alone() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let old_id = Uuid::new_v4();
        let mut old_cleared = alert(
            old_id,
            "10.0.0.1",
            "a",
            AlertState::Cleared,
            AlertLevel::Info,
        );
        old_cleared.cleared_at = Some(chrono::Utc::now() - chrono::Duration::days(30));
        store.upsert(&old_cleared).await.unwrap();

        let recent_id = Uuid::new_v4();
        store
            .upsert(&alert(
                recent_id,
                "10.0.0.2",
                "b",
                AlertState::Cleared,
                AlertLevel::Info,
            ))
            .await
            .unwrap();

        let active_id = Uuid::new_v4();
        store
            .upsert(&alert(
                active_id,
                "10.0.0.3",
                "c",
                AlertState::Active,
                AlertLevel::Info,
            ))
            .await
            .unwrap();

        let cutoff = chrono::Utc::now() - chrono::Duration::days(7);
        let deleted = store.prune_cleared_older_than(cutoff).await.unwrap();
        assert_eq!(deleted, 1, "only the old cleared alert must be pruned");

        let remaining = store.list(&AlertListQuery::default()).await.unwrap();
        assert_eq!(remaining.total, 2);
        assert!(
            remaining.items.iter().any(|a| a.id == recent_id),
            "a recently-cleared alert must survive"
        );
        assert!(
            remaining.items.iter().any(|a| a.id == active_id),
            "an active alert must never be pruned regardless of age"
        );
    }

    #[tokio::test]
    async fn get_returns_none_for_an_unknown_id_and_some_after_upsert() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let id = Uuid::new_v4();
        assert!(store.get(id).await.unwrap().is_none());
        store
            .upsert(&alert(
                id,
                "10.0.0.1",
                "high_cpu",
                AlertState::Active,
                AlertLevel::Warning,
            ))
            .await
            .unwrap();
        assert_eq!(store.get(id).await.unwrap().unwrap().id, id);
    }

    #[tokio::test]
    async fn delete_removes_the_row_and_is_a_noop_for_an_unknown_id() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let id = Uuid::new_v4();
        store
            .upsert(&alert(
                id,
                "10.0.0.1",
                "high_cpu",
                AlertState::Active,
                AlertLevel::Warning,
            ))
            .await
            .unwrap();
        store.delete(id).await.unwrap();
        assert!(store.get(id).await.unwrap().is_none());
        store.delete(Uuid::new_v4()).await.unwrap(); // no such id — must not error
    }

    #[tokio::test]
    async fn add_comment_appends_to_the_thread_in_order_and_bumps_comment_count() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let id = Uuid::new_v4();
        let original = alert(
            id,
            "10.0.0.1",
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        );
        store.upsert(&original).await.unwrap();
        assert_eq!(store.get(id).await.unwrap().unwrap().comment_count, 0);

        let first = store
            .add_comment(id, "alice", "looked into it, waiting on vendor", vec![])
            .await
            .unwrap();
        assert_eq!(first.author, "alice");
        assert_eq!(first.text, "looked into it, waiting on vendor");
        let second = store
            .add_comment(id, "bob", "vendor replied, patching tonight", vec![])
            .await
            .unwrap();

        let fetched = store.get(id).await.unwrap().unwrap();
        assert_eq!(fetched.comment_count, 2);
        assert_eq!(
            fetched.message, original.message,
            "adding a comment must not touch other alert fields"
        );

        let thread = store.list_comments(id).await.unwrap();
        assert_eq!(thread.len(), 2);
        assert_eq!(thread[0].id, first.id, "oldest first");
        assert_eq!(thread[1].id, second.id);

        // No such alert — must error, not silently no-op (see `AlertStore::add_comment`'s docs).
        assert!(store
            .add_comment(Uuid::new_v4(), "carol", "x", vec![])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn add_comment_with_attachments_stores_metadata_and_bytes_separately() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let id = Uuid::new_v4();
        store
            .upsert(&alert(
                id,
                "10.0.0.1",
                "high_cpu",
                AlertState::Active,
                AlertLevel::Warning,
            ))
            .await
            .unwrap();

        let comment = store
            .add_comment(
                id,
                "alice",
                "see attached",
                vec![NewAttachment {
                    filename: "screenshot.png".to_string(),
                    content_type: "image/png".to_string(),
                    data: vec![1, 2, 3, 4],
                }],
            )
            .await
            .unwrap();
        assert_eq!(comment.attachments.len(), 1);
        assert_eq!(comment.attachments[0].filename, "screenshot.png");
        assert_eq!(comment.attachments[0].size, 4);

        // list_comments must round-trip the same metadata without needing the bytes.
        let thread = store.list_comments(id).await.unwrap();
        assert_eq!(thread[0].attachments.len(), 1);
        assert_eq!(thread[0].attachments[0].id, comment.attachments[0].id);

        let (meta, data) = store
            .get_attachment(comment.attachments[0].id)
            .await
            .unwrap()
            .expect("attachment must exist");
        assert_eq!(meta.content_type, "image/png");
        assert_eq!(data, vec![1, 2, 3, 4]);

        assert!(store
            .get_attachment(Uuid::new_v4())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn deleting_an_alert_cascades_its_comments() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let id = Uuid::new_v4();
        store
            .upsert(&alert(
                id,
                "10.0.0.1",
                "high_cpu",
                AlertState::Active,
                AlertLevel::Warning,
            ))
            .await
            .unwrap();
        let comment = store
            .add_comment(
                id,
                "alice",
                "note",
                vec![NewAttachment {
                    filename: "a.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    data: vec![9],
                }],
            )
            .await
            .unwrap();

        store.delete(id).await.unwrap();
        assert_eq!(
            store.list_comments(id).await.unwrap().len(),
            0,
            "comments must not survive their alert's deletion"
        );
        assert!(
            store
                .get_attachment(comment.attachments[0].id)
                .await
                .unwrap()
                .is_none(),
            "an attachment must not survive its comment's cascaded deletion"
        );
    }

    #[tokio::test]
    async fn delete_for_device_removes_only_that_devices_alerts() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        let a = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        );
        let b = alert(
            Uuid::new_v4(),
            "10.0.0.2",
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        );
        store.upsert(&a).await.unwrap();
        store.upsert(&b).await.unwrap();

        let deleted = store.delete_for_device(a.device_id).await.unwrap();
        assert_eq!(deleted, 1);
        assert!(store.get(a.id).await.unwrap().is_none());
        assert!(
            store.get(b.id).await.unwrap().is_some(),
            "an unrelated device's alerts must survive"
        );

        // No such device — must not error, must delete nothing.
        assert_eq!(store.delete_for_device(Uuid::new_v4()).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn active_counts_by_device_counts_only_active_and_only_the_requested_devices() {
        let store = SeaOrmAlertStore::new_in_memory_for_tests().await;
        // `alert()` gives every call an unrelated random `device_id` regardless of
        // `device_ip` — force a2/a3 onto the same device as a1 explicitly.
        let a1 = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        );
        let mut a2 = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "high_memory",
            AlertState::Active,
            AlertLevel::Critical,
        );
        a2.device_id = a1.device_id;
        let mut a3 = alert(
            Uuid::new_v4(),
            "10.0.0.1",
            "flapping",
            AlertState::Cleared,
            AlertLevel::Warning,
        );
        a3.device_id = a1.device_id; // same device as a1/a2 — its cleared alert must not count
        let b1 = alert(
            Uuid::new_v4(),
            "10.0.0.2",
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        );
        let c1 = alert(
            Uuid::new_v4(),
            "10.0.0.3",
            "high_cpu",
            AlertState::Active,
            AlertLevel::Warning,
        ); // never included in the query below

        for a in [&a1, &a2, &a3, &b1, &c1] {
            store.upsert(a).await.unwrap();
        }

        let counts = store
            .active_counts_by_device(&[a1.device_id, b1.device_id])
            .await
            .unwrap();
        assert_eq!(
            counts.get(&a1.device_id),
            Some(&2),
            "two active alerts, cleared one excluded"
        );
        assert_eq!(counts.get(&b1.device_id), Some(&1));
        assert_eq!(
            counts.get(&c1.device_id),
            None,
            "not in the requested id list, even though it has an active alert"
        );

        assert_eq!(
            store.active_counts_by_device(&[]).await.unwrap(),
            HashMap::new()
        );
    }
}
