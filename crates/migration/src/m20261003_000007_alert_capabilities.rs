use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        for (table, column) in [
            ("profile_alerts", "policy"),
            ("alerts", "details"),
            ("notification_rules", "selection"),
        ] {
            if !m.has_column(table, column).await? {
                m.alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .add_column(ColumnDef::new(Alias::new(column)).json())
                        .to_owned(),
                )
                .await?;
            }
        }
        for column in [
            "response_required",
            "response_escalated",
            "screen_notification",
        ] {
            if !m.has_column("alerts", column).await? {
                m.alter_table(
                    Table::alter()
                        .table(Alias::new("alerts"))
                        .add_column(
                            ColumnDef::new(Alias::new(column))
                                .boolean()
                                .not_null()
                                .default(false),
                        )
                        .to_owned(),
                )
                .await?;
            }
        }
        m.create_index(
            Index::create()
                .name("idx_alert_screen_pending")
                .table(Alias::new("alerts"))
                .col(Alias::new("screen_notification"))
                .col(Alias::new("acknowledged_at"))
                .to_owned(),
        )
        .await?;
        m.create_index(
            Index::create()
                .name("idx_alert_response_pending")
                .table(Alias::new("alerts"))
                .col(Alias::new("response_required"))
                .col(Alias::new("acknowledged_at"))
                .to_owned(),
        )
        .await?;
        m.create_table(
            Table::create()
                .table(Alias::new("alert_runtime"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("device_id"))
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(Alias::new("snapshot")).json().not_null())
                .to_owned(),
        )
        .await?;
        m.create_table(
            Table::create()
                .table(Alias::new("alert_rule_definitions"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("name"))
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(Alias::new("definition")).json().not_null())
                .to_owned(),
        )
        .await?;
        m.create_table(
            Table::create()
                .table(Alias::new("alert_source_events"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Alias::new("id"))
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(Alias::new("device_id")).uuid().not_null())
                .col(ColumnDef::new(Alias::new("metric")).string().not_null())
                .col(
                    ColumnDef::new(Alias::new("received_at"))
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(ColumnDef::new(Alias::new("data")).json().not_null())
                .to_owned(),
        )
        .await?;
        m.create_index(
            Index::create()
                .name("alert_source_events_device_time")
                .table(Alias::new("alert_source_events"))
                .col(Alias::new("device_id"))
                .col(Alias::new("received_at"))
                .to_owned(),
        )
        .await?;
        Ok(())
    }
    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            "alert_source_events",
            "alert_runtime",
            "alert_rule_definitions",
        ] {
            m.drop_table(Table::drop().table(Alias::new(table)).to_owned())
                .await?;
        }
        Ok(())
    }
}
