use async_trait::async_trait;
use chrono::{DateTime, Utc};
use discovery_core::SortDir;
use serde::Serialize;
use uuid::Uuid;

/// One audit-trail record — who did what, in which functional area, when. Direct user
/// request: "журнал... хранить в себе все действия пользователей: что за пользователь, в
/// каком домене и что за действие". `method`/`path` are kept alongside the human-readable
/// `action` purely for troubleshooting/REST-completeness — the dashboard's own Журнал page
/// only ever shows `action`.
#[derive(Debug, Clone, Serialize)]
pub struct JournalEntry {
    pub id: Uuid,
    pub ts: DateTime<Utc>,
    /// Plain text, not a foreign key — see `discovery_entities::journal_entries::Model::username`'s
    /// docs for why (same discipline `AlertComment::author`/`Alert::closed_by` use).
    pub username: String,
    /// Usually a `discovery_core::Domain::as_str()` value, plus `"users"`/`"roles"` for
    /// the two admin-only route groups that aren't one of the 8 routed domains — see
    /// `discovery_entities::journal_entries::Model::domain`'s docs.
    pub domain: String,
    pub action: String,
    pub method: String,
    pub path: String,
    /// Short identifier of the specific thing acted on (a profile/discovery config name,
    /// a device IP, a role name, ...) — `None` for fleet-wide/singleton actions with no
    /// single object. Plain text, not folded into `details`, specifically so it's
    /// cheaply searchable via the same free-text `search` this domain already supports.
    pub object: Option<String>,
    /// A small before/after diff (edit) or a few named counters (e.g. "N jobs deleted") —
    /// never a full copy of the edited entity, never a password/SNMP community. See
    /// `discovery_web::json_diff`/`redact_sensitive`'s docs (the crate that populates
    /// this) for the size-capping/redaction discipline. `None` for actions with nothing
    /// meaningful to record beyond `action`/`object` themselves (e.g. create, most
    /// deletes).
    pub details: Option<serde_json::Value>,
}

/// Which column to sort journal records by — see [`JournalListQuery`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalSortBy {
    Ts,
    Username,
    Domain,
    Action,
}

/// Search + filter + sort + paginate parameters for [`JournalStore::list`] — same
/// shape/conventions as `discovery_alerts::AlertListQuery`, which the dashboard's Журнал
/// page (added alongside this crate) mirrors just like it mirrors the Тревоги page.
#[derive(Debug, Clone)]
pub struct JournalListQuery {
    /// Free-text, case-insensitive, matched against username, domain, action, and path.
    pub search: Option<String>,
    /// `None` means every domain, not just one.
    pub domain: Option<String>,
    /// `None` means every user.
    pub username: Option<String>,
    /// Inclusive lower/upper bound on `JournalEntry::ts`. `None` on either side means
    /// unbounded on that side.
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub sort_by: JournalSortBy,
    pub sort_dir: SortDir,
    pub limit: i64,
    pub offset: i64,
}

impl Default for JournalListQuery {
    fn default() -> Self {
        Self {
            search: None,
            domain: None,
            username: None,
            since: None,
            until: None,
            sort_by: JournalSortBy::Ts,
            sort_dir: SortDir::Desc,
            limit: 50,
            offset: 0,
        }
    }
}

/// One page of journal records plus the total count matching the filter (ignoring
/// `limit`/`offset`) — same "page N of M, K total" shape as `discovery_alerts::AlertListPage`.
#[derive(Debug, Clone, Serialize)]
pub struct JournalListPage {
    pub items: Vec<JournalEntry>,
    pub total: i64,
}

/// Durable audit trail — see this module's docs. **[`Self::append`] is the single write
/// path**, called by `discovery-web`'s `require_domain_permission`/`require_admin`
/// middleware after every successful (2xx) mutating request; append-only, no update, no
/// per-entry delete (only bulk retention pruning) — an audit log that could be edited
/// after the fact wouldn't be one.
///
/// One implementation — [`crate::SeaOrmJournalStore`], works against Postgres/MySQL/SQLite
/// (and, for tests/zero-config, `sqlite::memory:`) through the same sea-orm entity/query
/// code path every other domain store in this project uses. Not one of the 8 routed
/// domains (see `discovery_entities::journal_entries`'s docs) — always constructed against
/// whichever connection `Domain::Settings` resolves to, same as `discovery_auth::AuthStore`.
#[async_trait]
pub trait JournalStore: Send + Sync {
    async fn append(&self, entry: &JournalEntry) -> anyhow::Result<()>;

    async fn list(&self, query: &JournalListQuery) -> anyhow::Result<JournalListPage>;

    /// Deletes every row older than `cutoff` — same contract as
    /// `discovery_logging::LogStore::prune_older_than`. Returns how many rows were
    /// deleted, purely for the cleanup loop's own logging.
    async fn prune_older_than(&self, cutoff: DateTime<Utc>) -> anyhow::Result<u64>;
}
