//! Actually placing a notification call — the delivery half of the notification channels +
//! matrix feature (2026-09-10, direct user request: "Реализуй каналы нотификации + матрицу
//! нотификации"). The *policy* half (which channels get notified for which alert — the
//! notification matrix, `discovery_config_store::NotificationRule`) deliberately never
//! reaches this crate at all; only `discovery_agent::handlers::AlertEvalHandler` (which
//! already depends on `discovery-config-store`) needs it, to decide *which*
//! `discovery_core::NotificationChannel`s to hand to [`Notifier::send`] here. Mirrors
//! `discovery-ping`/`discovery-servicecheck`'s real/fake split — and, like those two, only
//! depends on `discovery-core`, not on `discovery-config-store`, so it can be reused by a
//! future distributed collector binary without dragging in a database driver.

mod fake;
mod format;
mod notifier;
mod real;

pub use fake::*;
pub use format::*;
pub use notifier::*;
pub use real::*;
