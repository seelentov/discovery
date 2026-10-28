//! Ties every crate together: worker pools per queue, the profile pipeline handlers, and
//! the dashboard web server. Also exposed as a library so integration/e2e tests can drive
//! the exact same handlers as the binary.
//!
//! Relocated here from `Cargo.toml`'s `[package].description` 2026-09-12 (Linux `.deb`/
//! `.rpm` packaging) — `cargo-deb` uses that field verbatim as the package's customer-
//! facing `Description` summary (no separate override field exists in this version), so
//! it now holds a short customer-facing line instead; this engineering-facing explanation
//! moved here, where it's actually read by the audience it's for.

pub mod alert_history_cleanup;
pub mod config_backup_schedule;
pub mod dead_device_cleanup;
pub mod demo;
pub mod discovery_scan;
pub mod group_alert;
pub mod handlers;
mod ingest_retry;
pub mod journal_cleanup;
pub mod log_cleanup;
pub mod logging_setup;
pub mod login_rate_limit_sweep;
pub mod metric_history_cleanup;
pub mod notification_dispatch;
pub mod operator_actions;
pub mod profile_reload;
mod rate_limit;
pub mod session_cleanup;
pub mod syslog_decode;
pub mod syslog_ingest;
pub mod syslog_listener;
pub mod syslog_ttl_sweep;
pub mod topology_recompute;
pub mod trap_ingest;
pub mod trap_listener;
pub mod trap_ttl_sweep;

mod alert_rules;

pub mod alert_schedule;
