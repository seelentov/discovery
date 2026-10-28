mod buffer;
mod layer;
mod store;

pub use buffer::*;
pub use layer::*;
pub use store::*;

/// Logs at ERROR severity with a marker that [`BufferLayer`] relabels as `"FATAL"` for
/// display/filtering. `tracing::Level` is a fixed enum (TRACE/DEBUG/INFO/WARN/ERROR) —
/// there's no real FATAL variant to add to it — so this is ERROR-plus-a-tag, not a
/// separate tracing level. Console/file sinks (plain `tracing_subscriber::fmt` layers)
/// still show these as `ERROR` with a `fatal=true` field, since a `Filter` only sees
/// event *metadata* (level + declared field names), never field *values*, so it's not
/// possible to give the console/file layers "FATAL" as a genuinely distinct filterable
/// severity without a custom `Layer` — only the dashboard buffer (which inspects values
/// after the fact, in `BufferLayer::on_event`) can. Filtering at `"error"` on any sink
/// always includes fatals too, since they *are* ERROR underneath.
///
/// Conventionally paired with terminating the process — see `discovery-agent`'s `main()`,
/// which calls this for any error that aborts startup.
#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => {
        tracing::error!(fatal = true, $($arg)*)
    };
}
