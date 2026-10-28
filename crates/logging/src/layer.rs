use std::collections::BTreeMap;
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

use crate::{LogBuffer, LogEntry};

/// A `tracing_subscriber::Layer` that captures every event into a [`LogBuffer`] — install
/// it alongside the console/file layers (each with its own level filter, since `Layer`s
/// compose independently) to feed the dashboard's `/api/logs`.
pub struct BufferLayer {
    buffer: Arc<LogBuffer>,
}

impl BufferLayer {
    pub fn new(buffer: Arc<LogBuffer>) -> Self {
        Self { buffer }
    }
}

impl<S: Subscriber> Layer<S> for BufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        self.buffer.push(build_entry(event));
    }
}

/// Shared by [`BufferLayer`] and [`PersistingLayer`] — both need to turn a raw `tracing`
/// event into the same [`LogEntry`] shape, including the FATAL-relabeling trick (see
/// `crate::fatal!`'s docs for why that can only happen here, not via `EnvFilter`).
fn build_entry(event: &Event<'_>) -> LogEntry {
    let mut visitor = FieldVisitor::default();
    event.record(&mut visitor);

    let is_fatal = *event.metadata().level() == tracing::Level::ERROR
        && visitor.fields.get("fatal").map(String::as_str) == Some("true");
    let level = if is_fatal {
        visitor.fields.remove("fatal");
        "FATAL".to_string()
    } else {
        event.metadata().level().to_string()
    };

    LogEntry {
        timestamp: chrono::Utc::now(),
        level,
        target: event.metadata().target().to_string(),
        message: visitor.message.unwrap_or_default(),
        fields: visitor.fields,
    }
}

/// A `tracing_subscriber::Layer` that forwards every event to a [`crate::LogStore`] for
/// durable persistence (Sqlite/Postgres — see `crate::store`), independently of the
/// in-memory [`BufferLayer`] tail the dashboard reads from. `Layer::on_event` is
/// synchronous and `LogStore::append` is async, so this never awaits inline — it tries to
/// send the built entry to a bounded channel and a background task
/// (`crate::store::spawn_log_persister`) drains it and calls the store. When the store is
/// stalled, durable log entries may be dropped once the queue is full; that is preferable
/// to allowing a logging outage to exhaust memory and stop monitoring. The dashboard tail
/// remains independently bounded by `LogBuffer`.
pub struct PersistingLayer {
    sender: tokio::sync::mpsc::Sender<LogEntry>,
}

impl PersistingLayer {
    pub fn new(sender: tokio::sync::mpsc::Sender<LogEntry>) -> Self {
        Self { sender }
    }
}

impl<S: Subscriber> Layer<S> for PersistingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // A closed/full receiver is deliberately a dropped best-effort durable copy, not a
        // reason to block the application or emit another tracing event into this pipeline.
        let _ = self.sender.try_send(build_entry(event));
    }
}

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    fields: BTreeMap<String, String>,
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // `record_str` already handled plain string fields (the common case for our
        // `field = %value` / `field = value` log call sites); this catches everything
        // else (numbers, `Debug`-only types) via `{:?}` formatting.
        let formatted = format!("{:?}", value);
        if field.name() == "message" {
            self.message.get_or_insert(formatted);
        } else {
            self.fields
                .entry(field.name().to_string())
                .or_insert(formatted);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn captures_level_target_message_and_fields() {
        let buffer = Arc::new(LogBuffer::new(10));
        let subscriber = tracing_subscriber::registry().with(BufferLayer::new(buffer.clone()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(device_id = "abc-123", ip = "10.0.0.1", "something happened");
        });

        let entries = buffer.snapshot(None, None, None, None, None);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.level, "WARN");
        assert_eq!(entry.message, "something happened");
        assert_eq!(entry.fields.get("device_id"), Some(&"abc-123".to_string()));
        assert_eq!(entry.fields.get("ip"), Some(&"10.0.0.1".to_string()));
    }

    #[test]
    fn fatal_macro_is_relabeled_and_the_marker_field_is_not_duplicated() {
        let buffer = Arc::new(LogBuffer::new(10));
        let subscriber = tracing_subscriber::registry().with(BufferLayer::new(buffer.clone()));

        tracing::subscriber::with_default(subscriber, || {
            crate::fatal!(reason = "db unreachable", "startup failed");
        });

        let entries = buffer.snapshot(None, None, None, None, None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].level, "FATAL");
        assert_eq!(entries[0].message, "startup failed");
        assert_eq!(
            entries[0].fields.get("reason"),
            Some(&"db unreachable".to_string())
        );
        assert!(
            !entries[0].fields.contains_key("fatal"),
            "the fatal marker itself shouldn't leak into displayed fields"
        );
    }

    #[test]
    fn a_plain_error_without_the_fatal_marker_stays_error() {
        let buffer = Arc::new(LogBuffer::new(10));
        let subscriber = tracing_subscriber::registry().with(BufferLayer::new(buffer.clone()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!("just a regular error");
        });

        assert_eq!(
            buffer.snapshot(None, None, None, None, None)[0].level,
            "ERROR"
        );
    }

    #[test]
    fn persisting_layer_drops_when_its_bounded_queue_is_full() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let subscriber = tracing_subscriber::registry().with(PersistingLayer::new(sender));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("first");
            tracing::info!("second");
        });

        assert_eq!(receiver.try_recv().unwrap().message, "first");
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }
}
