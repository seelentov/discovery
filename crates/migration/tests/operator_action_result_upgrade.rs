use discovery_entities::jobs::{ActiveModel, Entity};
use discovery_migration::Migrator;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait, Database, EntityTrait};
use sea_orm_migration::MigratorTrait;

#[tokio::test]
async fn adds_result_to_existing_jobs_without_losing_rows() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let now = chrono::Utc::now();
    let id = ActiveModel {
        id: sea_orm::ActiveValue::NotSet,
        queue_type: Set("discovery".to_string()),
        payload: Set(serde_json::json!({"ip": "192.0.2.12"})),
        dedupe_key: Set(None),
        state: Set("pending".to_string()),
        attempts: Set(0),
        max_attempts: Set(5),
        locked_by: Set(None),
        locked_at: Set(None),
        last_error: Set(None),
        result: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
        paused: Set(false),
    }
    .insert(&db)
    .await
    .unwrap()
    .id;
    db.execute_unprepared(
        "DELETE FROM seaql_migrations WHERE version = 'm20260925_000005_operator_action_result'",
    )
    .await
    .unwrap();
    db.execute_unprepared("ALTER TABLE jobs DROP COLUMN result")
        .await
        .unwrap();
    assert!(Entity::find_by_id(id).one(&db).await.is_err());
    Migrator::up(&db, None).await.unwrap();
    let restored = Entity::find_by_id(id).one(&db).await.unwrap().unwrap();
    assert_eq!(restored.payload["ip"], "192.0.2.12");
    assert_eq!(restored.result, None);
}
