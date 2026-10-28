//! Adds alert hysteresis/flapping columns to already-migrated installations.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, column, definition) in [
            (
                "profile_alerts",
                "activate_after_seconds",
                ProfileAlertColumns::ActivateAfterSeconds,
            ),
            (
                "profile_alerts",
                "flap_window_seconds",
                ProfileAlertColumns::FlapWindowSeconds,
            ),
            (
                "profile_alerts",
                "flap_threshold",
                ProfileAlertColumns::FlapThreshold,
            ),
        ] {
            if !manager.has_column(table, column).await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(ProfileAlerts::Table)
                            .add_column(ColumnDef::new(definition).big_integer())
                            .to_owned(),
                    )
                    .await?;
            }
        }
        if !manager.has_column("alerts", "flapping").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alerts::Table)
                        .add_column(
                            ColumnDef::new(Alerts::Flapping)
                                .boolean()
                                .not_null()
                                .default(false),
                        )
                        .to_owned(),
                )
                .await?;
        }
        if !manager.has_column("alerts", "suppression_reason").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alerts::Table)
                        .add_column(ColumnDef::new(Alerts::SuppressionReason).text())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[derive(DeriveIden)]
enum ProfileAlerts {
    Table,
}

#[derive(DeriveIden)]
enum ProfileAlertColumns {
    ActivateAfterSeconds,
    FlapWindowSeconds,
    FlapThreshold,
}

#[derive(DeriveIden)]
enum Alerts {
    Table,
    Flapping,
    SuppressionReason,
}
