//! Durable acknowledgement and notification-snooze state for alert incidents.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (name, column) in [
            ("acknowledged_by", Column::AcknowledgedBy),
            ("acknowledged_at", Column::AcknowledgedAt),
            ("snoozed_until", Column::SnoozedUntil),
            ("snoozed_by", Column::SnoozedBy),
        ] {
            if !manager.has_column("alerts", name).await? {
                let statement = match column {
                    Column::AcknowledgedBy => Table::alter()
                        .table(Alerts::Table)
                        .add_column(ColumnDef::new(Column::AcknowledgedBy).text())
                        .to_owned(),
                    Column::AcknowledgedAt => Table::alter()
                        .table(Alerts::Table)
                        .add_column(
                            ColumnDef::new(Column::AcknowledgedAt).timestamp_with_time_zone(),
                        )
                        .to_owned(),
                    Column::SnoozedUntil => Table::alter()
                        .table(Alerts::Table)
                        .add_column(ColumnDef::new(Column::SnoozedUntil).timestamp_with_time_zone())
                        .to_owned(),
                    Column::SnoozedBy => Table::alter()
                        .table(Alerts::Table)
                        .add_column(ColumnDef::new(Column::SnoozedBy).text())
                        .to_owned(),
                };
                manager.alter_table(statement).await?;
            }
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Alerts {
    Table,
}

#[derive(DeriveIden)]
enum Column {
    AcknowledgedBy,
    AcknowledgedAt,
    SnoozedUntil,
    SnoozedBy,
}
