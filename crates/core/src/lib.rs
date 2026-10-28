//! `discovery-core` — the shared vocabulary of the whole system: what a device is, what a
//! metric is, what an alert is, what a queued job looks like. No async runtime, no HTTP,
//! no SQL here — those live in the crates that depend on this one (`snmp`, `queue`,
//! `web`, `agent`). Keeping this crate dependency-free (besides serde/chrono/uuid) means
//! it can be reused by a future distributed collector binary without dragging in a web
//! server or a database driver.

pub mod active_chains;
pub mod ai_assistant;
pub mod alert;
pub mod alert_retention;
pub mod alert_state;
pub mod config_backup;
pub mod dead_device_retention;
pub mod device;
pub mod domain;
pub mod journal_retention;
pub mod log_retention;
pub mod metrics;
pub mod notification;
pub mod payload;
pub mod ping_config;
pub mod poll_intervals;
pub mod queue;
pub mod rate_limit;
pub mod schedule;
pub mod secret;
pub mod sort;
pub mod trap_engine_state;
pub mod worker_status;

pub use active_chains::*;
pub use ai_assistant::*;
pub use alert::*;
pub use alert_retention::*;
pub use alert_state::*;
pub use config_backup::*;
pub use dead_device_retention::*;
pub use device::*;
pub use domain::*;
pub use journal_retention::*;
pub use log_retention::*;
pub use metrics::*;
pub use notification::*;
pub use ping_config::*;
pub use poll_intervals::*;
pub use queue::*;
pub use rate_limit::*;
pub use schedule::*;
pub use secret::*;
pub use sort::*;
pub use trap_engine_state::*;
pub use worker_status::*;

pub mod alert_policy;
pub mod alert_runtime;
pub use alert_policy::*;
pub use alert_runtime::*;
