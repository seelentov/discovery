use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, column, def) in [
            (
                "alerts",
                "repeat_count",
                ColumnDef::new(Alias::new("repeat_count"))
                    .integer()
                    .not_null()
                    .default(0),
            ),
            (
                "alerts",
                "escalation_level",
                ColumnDef::new(Alias::new("escalation_level"))
                    .integer()
                    .not_null()
                    .default(0),
            ),
            (
                "alerts",
                "repeated_at",
                ColumnDef::new(Alias::new("repeated_at")).timestamp().null(),
            ),
            (
                "alerts",
                "escalation_reason",
                ColumnDef::new(Alias::new("escalation_reason"))
                    .string()
                    .null(),
            ),
            (
                "notification_rules",
                "repeat_after_seconds",
                ColumnDef::new(Alias::new("repeat_after_seconds"))
                    .big_integer()
                    .not_null()
                    .default(0),
            ),
            (
                "notification_rules",
                "repeat_interval_seconds",
                ColumnDef::new(Alias::new("repeat_interval_seconds"))
                    .big_integer()
                    .not_null()
                    .default(0),
            ),
            (
                "notification_rules",
                "max_repeats",
                ColumnDef::new(Alias::new("max_repeats"))
                    .integer()
                    .not_null()
                    .default(0),
            ),
            (
                "notification_rules",
                "escalation_levels",
                ColumnDef::new(Alias::new("escalation_levels"))
                    .json()
                    .null(),
            ),
        ] {
            if !manager.has_column(table, column).await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Alias::new(table))
                            .add_column(def)
                            .to_owned(),
                    )
                    .await?;
            }
        }
        Ok(())
    }
}
