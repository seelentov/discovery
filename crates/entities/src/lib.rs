//! One sea-orm `DeriveEntityModel` per table — the single, backend-agnostic schema
//! definition every domain store's sea-orm implementation queries against (Postgres/
//! MySQL/SQLite from one code path). See `discovery/README.md`'s "Мульти-БД поддержка"
//! section for why this replaced the old per-crate hand-written `Postgres*`/`Sqlite*`
//! query pairs, and `crates/migration` for the DDL that actually creates these tables
//! (this crate only maps onto them, it does not create them).
//!
//! Table/column names are unchanged from the pre-2026-08-18 hand-written schema — see
//! each module's docs for which `migrations/*.sql` file it mirrors — so existing data on
//! an already-running Postgres deployment keeps working without a data migration, only
//! the code reading/writing it changed.

pub mod alert_comment_attachments;
pub mod alert_comments;
pub mod alerts;
pub mod assistant_conversations;
pub mod assistant_messages;
pub mod device_metric_history;
pub mod device_metric_settings;
pub mod device_metrics;
pub mod devices;
pub mod discovery_configs;
pub mod discovery_subnet_labels;
pub mod discovery_subnet_oids;
pub mod discovery_subnets;
pub mod group_alert_rules;
pub mod jobs;
pub mod journal_entries;
pub mod logs;
pub mod maintenance_windows;
pub mod notification_channels;
pub mod notification_rules;
pub mod profile_alerts;
pub mod profile_metrics;
pub mod profile_service_checks;
pub mod profile_syslog;
pub mod profile_traps;
pub mod profiles;
pub mod queue_control;
pub mod role_permissions;
pub mod roles;
pub mod sessions;
pub mod settings;
pub mod topology_claims;
pub mod topology_device_keys;
pub mod topology_hierarchy_overrides;
pub mod topology_rules;
pub mod users;

pub mod alert_rule_definitions;
pub mod alert_runtime;
pub mod alert_source_events;
