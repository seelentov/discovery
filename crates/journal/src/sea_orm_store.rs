use async_trait::async_trait;
use discovery_entities::journal_entries::{ActiveModel, Column, Entity, Model};
use sea_orm::sea_query::{Expr, Func};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, Condition, DatabaseConnection, EntityTrait, Order,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect,
};

use crate::{JournalEntry, JournalListPage, JournalListQuery, JournalSortBy, JournalStore};

fn sort_column(sort_by: JournalSortBy) -> Column {
    match sort_by {
        JournalSortBy::Ts => Column::Ts,
        JournalSortBy::Username => Column::Username,
        JournalSortBy::Domain => Column::Domain,
        JournalSortBy::Action => Column::Action,
    }
}

fn model_to_entry(m: Model) -> JournalEntry {
    JournalEntry {
        id: m.id,
        ts: m.ts,
        username: m.username,
        domain: m.domain,
        action: m.action,
        method: m.method,
        path: m.path,
        object: m.object,
        details: m.details,
    }
}

/// The sea-orm-backed implementation — see [`crate::JournalStore`]'s docs. Rows in
/// `journal_entries` (`discovery_entities::journal_entries`, `crates/migration`).
pub struct SeaOrmJournalStore {
    db: DatabaseConnection,
}

impl SeaOrmJournalStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Convenience for tests — see `discovery_config_store::SeaOrmSettingsStore::new_in_memory_for_tests`'s
    /// docs for why this exists and why it's async.
    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }
}

#[async_trait]
impl JournalStore for SeaOrmJournalStore {
    async fn append(&self, entry: &JournalEntry) -> anyhow::Result<()> {
        let am = ActiveModel {
            id: Set(entry.id),
            ts: Set(entry.ts),
            username: Set(entry.username.clone()),
            domain: Set(entry.domain.clone()),
            action: Set(entry.action.clone()),
            method: Set(entry.method.clone()),
            path: Set(entry.path.clone()),
            object: Set(entry.object.clone()),
            details: Set(entry.details.clone()),
        };
        Entity::insert(am).exec(&self.db).await?;
        Ok(())
    }

    async fn list(&self, query: &JournalListQuery) -> anyhow::Result<JournalListPage> {
        let mut cond = Condition::all();
        if let Some(search) = query.search.as_deref() {
            // `LOWER(col) LIKE %needle%` — same portable case-insensitive search
            // `discovery_alerts::SeaOrmAlertStore::list` uses, see its docs for why not
            // backend-specific `ILIKE`.
            let needle = format!("%{}%", search.to_lowercase());
            cond = cond.add(
                Condition::any()
                    .add(Expr::expr(Func::lower(Expr::col(Column::Username))).like(needle.clone()))
                    .add(Expr::expr(Func::lower(Expr::col(Column::Domain))).like(needle.clone()))
                    .add(Expr::expr(Func::lower(Expr::col(Column::Action))).like(needle.clone()))
                    .add(Expr::expr(Func::lower(Expr::col(Column::Path))).like(needle.clone()))
                    // `LOWER(NULL)` / `NULL LIKE ...` both evaluate to `NULL` (falsy) on
                    // every backend this project supports — no separate `IS NOT NULL`
                    // guard needed for the common case where `object` wasn't set.
                    .add(Expr::expr(Func::lower(Expr::col(Column::Object))).like(needle)),
            );
        }
        if let Some(domain) = query.domain.as_deref() {
            cond = cond.add(Column::Domain.eq(domain));
        }
        if let Some(username) = query.username.as_deref() {
            cond = cond.add(Column::Username.eq(username));
        }
        if let Some(since) = query.since {
            cond = cond.add(Column::Ts.gte(since));
        }
        if let Some(until) = query.until {
            cond = cond.add(Column::Ts.lte(until));
        }

        let total = Entity::find().filter(cond.clone()).count(&self.db).await? as i64;

        let order = if query.sort_dir == discovery_core::SortDir::Asc {
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

        let items = models.into_iter().map(model_to_entry).collect();
        Ok(JournalListPage { items, total })
    }

    async fn prune_older_than(&self, cutoff: chrono::DateTime<chrono::Utc>) -> anyhow::Result<u64> {
        let result = Entity::delete_many()
            .filter(Column::Ts.lt(cutoff))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn entry(username: &str, domain: &str, action: &str) -> JournalEntry {
        JournalEntry {
            id: Uuid::new_v4(),
            ts: Utc::now(),
            username: username.to_string(),
            domain: domain.to_string(),
            action: action.to_string(),
            method: "POST".to_string(),
            path: "/api/devices".to_string(),
            object: None,
            details: None,
        }
    }

    #[tokio::test]
    async fn append_then_list_round_trips() {
        let store = SeaOrmJournalStore::new_in_memory_for_tests().await;
        store
            .append(&entry("admin", "devices", "Создано устройство"))
            .await
            .unwrap();

        let page = store.list(&JournalListQuery::default()).await.unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].username, "admin");
        assert_eq!(page.items[0].domain, "devices");
        assert_eq!(page.items[0].action, "Создано устройство");
    }

    #[tokio::test]
    async fn object_and_details_round_trip_and_object_is_searchable() {
        let store = SeaOrmJournalStore::new_in_memory_for_tests().await;
        let mut e = entry("admin", "discovery_configs", "Изменён конфиг дискаверинга");
        e.object = Some("vor-hub".to_string());
        e.details = Some(serde_json::json!({"enabled": {"old": true, "new": false}}));
        store.append(&e).await.unwrap();
        store
            .append(&entry("admin", "discovery_configs", "unrelated"))
            .await
            .unwrap();

        let page = store.list(&JournalListQuery::default()).await.unwrap();
        assert_eq!(page.total, 2);
        let with_object = page
            .items
            .iter()
            .find(|i| i.object.as_deref() == Some("vor-hub"))
            .unwrap();
        assert_eq!(
            with_object.details,
            Some(serde_json::json!({"enabled": {"old": true, "new": false}}))
        );
        let without_object = page.items.iter().find(|i| i.action == "unrelated").unwrap();
        assert_eq!(without_object.object, None);
        assert_eq!(without_object.details, None);

        let by_object = store
            .list(&JournalListQuery {
                search: Some("vor-hub".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            by_object.total, 1,
            "search must match the object identifier, not just username/domain/action/path"
        );
        assert_eq!(by_object.items[0].object.as_deref(), Some("vor-hub"));
    }

    #[tokio::test]
    async fn append_is_never_an_upsert() {
        let store = SeaOrmJournalStore::new_in_memory_for_tests().await;
        store
            .append(&entry("admin", "devices", "first"))
            .await
            .unwrap();
        store
            .append(&entry("admin", "devices", "second"))
            .await
            .unwrap();

        let page = store.list(&JournalListQuery::default()).await.unwrap();
        assert_eq!(
            page.total, 2,
            "every append is a new row — an audit log that could overwrite itself wouldn't be one"
        );
    }

    #[tokio::test]
    async fn search_matches_username_domain_action_and_path() {
        let store = SeaOrmJournalStore::new_in_memory_for_tests().await;
        store
            .append(&entry("alice", "devices", "Удалено устройство"))
            .await
            .unwrap();
        store
            .append(&entry("bob", "profiles", "Сохранён профиль"))
            .await
            .unwrap();

        let by_user = store
            .list(&JournalListQuery {
                search: Some("alice".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_user.total, 1);
        assert_eq!(by_user.items[0].username, "alice");

        let by_action = store
            .list(&JournalListQuery {
                search: Some("профиль".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_action.total, 1);
        assert_eq!(by_action.items[0].username, "bob");
    }

    #[tokio::test]
    async fn domain_and_username_filters_are_exact_match() {
        let store = SeaOrmJournalStore::new_in_memory_for_tests().await;
        store.append(&entry("alice", "devices", "a")).await.unwrap();
        store
            .append(&entry("alice", "profiles", "b"))
            .await
            .unwrap();
        store.append(&entry("bob", "devices", "c")).await.unwrap();

        let page = store
            .list(&JournalListQuery {
                domain: Some("devices".to_string()),
                username: Some("alice".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].action, "a");
    }

    #[tokio::test]
    async fn since_until_bound_ts() {
        let store = SeaOrmJournalStore::new_in_memory_for_tests().await;
        let now = Utc::now();
        let mut old = entry("alice", "devices", "old");
        old.ts = now - chrono::Duration::hours(2);
        store.append(&old).await.unwrap();
        let mut recent = entry("alice", "devices", "recent");
        recent.ts = now - chrono::Duration::minutes(1);
        store.append(&recent).await.unwrap();

        let page = store
            .list(&JournalListQuery {
                since: Some(now - chrono::Duration::hours(1)),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].action, "recent");
    }

    #[tokio::test]
    async fn sort_and_pagination() {
        let store = SeaOrmJournalStore::new_in_memory_for_tests().await;
        for name in ["charlie", "alice", "bob"] {
            store.append(&entry(name, "devices", "x")).await.unwrap();
        }

        let page = store
            .list(&JournalListQuery {
                sort_by: JournalSortBy::Username,
                sort_dir: discovery_core::SortDir::Asc,
                limit: 2,
                offset: 0,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].username, "alice");
        assert_eq!(page.items[1].username, "bob");

        let page2 = store
            .list(&JournalListQuery {
                sort_by: JournalSortBy::Username,
                sort_dir: discovery_core::SortDir::Asc,
                limit: 2,
                offset: 2,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 1);
        assert_eq!(page2.items[0].username, "charlie");
    }

    #[tokio::test]
    async fn prune_older_than_deletes_only_rows_before_the_cutoff() {
        let store = SeaOrmJournalStore::new_in_memory_for_tests().await;
        let now = Utc::now();
        let mut old = entry("alice", "devices", "old");
        old.ts = now - chrono::Duration::hours(2);
        store.append(&old).await.unwrap();
        let mut recent = entry("alice", "devices", "recent");
        recent.ts = now - chrono::Duration::minutes(1);
        store.append(&recent).await.unwrap();

        let deleted = store
            .prune_older_than(now - chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        let page = store.list(&JournalListQuery::default()).await.unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].action, "recent");
    }
}
