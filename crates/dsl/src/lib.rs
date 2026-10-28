//! The profile DSL. Deliberately two small hooks, not a general-purpose language:
//!
//! 1. **Matching** — given a device's identity facts, which profile applies?
//! 2. **Alerting** — given a device's latest metrics, is a given alert condition true?
//!
//! Everything else in a profile (`[metrics.poll]`, alert `level`/`message`/`clear_after_seconds`)
//! is plain declarative TOML — only the two places where you actually need a conditional
//! (`match.expression`, `alerts[].expression`) drop into a Rhai expression. This mirrors
//! AggreGate's expression language (`{ctx:variable}` style field access, ternary chains)
//! but trimmed to "only what's necessary": no DataTable, no bindings, no rulesets — a
//! device/metrics map and boolean expressions are enough for this job.

mod alerts;
mod derive_metric;
pub mod group_alerts;
mod matcher;
mod profile;
pub mod topology;
mod util;

pub use alerts::*;
pub use derive_metric::*;
pub use matcher::*;
pub use profile::*;
