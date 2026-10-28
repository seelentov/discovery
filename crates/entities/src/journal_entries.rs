//! `journal_entries` — the "Журнал" audit trail: who did what, in which functional area,
//! when. Written by `discovery-web`'s `require_domain_permission`/`require_admin`
//! middleware after every successful mutating (non-GET/HEAD) request — see that module's
//! `describe_action` docs. Lives wherever `Settings` resolves to, same "not one of the
//! routed domains" treatment as `users`/`sessions`/`roles` (see `discovery_auth`'s crate
//! docs) — an audit log about every domain doesn't belong to any single one of them.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "journal_entries")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub ts: DateTimeUtc,
    /// Plain text, not a `users.id` foreign key — same "record the actor's name at the
    /// time" discipline `alert_comments.author`/`alerts.closed_by` already use, so a
    /// journal entry keeps meaning something after the account that produced it is
    /// renamed or deleted.
    pub username: String,
    /// Functional area the action belongs to — usually a `discovery_core::Domain::as_str()`
    /// value, plus `"users"`/`"roles"` for the two admin-only route groups that aren't
    /// one of the 8 routed domains. Plain text (not an FK/enum column) since it's a
    /// descriptive label, not a storage-routing key.
    pub domain: String,
    /// Human-readable (Russian) description of what happened, e.g. "Удалено устройство" —
    /// see `discovery-web::describe_action`.
    pub action: String,
    pub method: String,
    pub path: String,
    /// Short identifier of the specific thing acted on — see `discovery_web::describe_action`'s
    /// sibling `object`/`details` plumbing. `None` for actions with no single object.
    pub object: Option<String>,
    /// Small before/after diff or a few named counters — never a copy of the whole
    /// edited entity, never a password/SNMP community (see `discovery_web::json_diff`/
    /// `redact_sensitive`'s docs).
    #[sea_orm(column_type = "Json", nullable)]
    pub details: Option<Json>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
