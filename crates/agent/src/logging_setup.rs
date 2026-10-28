use std::sync::Arc;

use discovery_bootstrap::LoggingConfig;
use discovery_logging::{BufferLayer, LogBuffer, LogEntry, PersistingLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// Installs the global tracing subscriber as four independently-filtered/routed sinks:
///
/// - console (`fmt::layer()`, filtered by `config.console_filter()`)
/// - file, if `config.file` is non-empty (rolling file appender, filtered by `file_filter()`)
/// - in-memory ring buffer for the dashboard's live tail (`BufferLayer`, filtered by
///   `dashboard_filter()` **plus a hardcoded `sqlx=off`**, see below) — always on, this
///   is what `/api/logs` reads
/// - durable persistence (`PersistingLayer`, filtered by `file_filter()` **plus the same
///   hardcoded `sqlx=off`**) — see the returned receiver's docs
///
/// **`sqlx=off` on `dashboard_layer`/`persisting_layer` is unconditional, not driven by
/// any config field** — added 2026-08-26 after a live incident ("запускал ненадолго и у
/// меня быстро собирались 100гб логов"). Root cause: `LogStore::append` (what
/// `spawn_log_persister` calls for every entry that reaches `persisting_layer`) is itself
/// a SQL `INSERT`, which sqlx traces as its own `sqlx::query` event — completed
/// (successful) queries log at INFO, not DEBUG (confirmed live: sqlx does *not* gate
/// normal completions behind a debug-only level, only a slow-query threshold bumps to
/// WARN). Before this fix, `persisting_layer` used `file_filter()` alone, which defaults
/// to a plain `"info"` — letting `sqlx::query` events straight through. The result is a
/// closed feedback loop with no dependency on real device/API traffic to sustain it:
/// persisting *any* event (including the ~40 idle worker-pool loops' own routine
/// `claim()` polling every 500ms-1s, see `discovery_queue::worker`) does an `INSERT`,
/// which fires a new `sqlx::query` event, which gets persisted, which fires another —
/// forever, at whatever rate the store can accept writes, completely unthrottled (the
/// persist channel is bounded and best-effort — see `PersistingLayer`'s docs — so a broken
/// log store cannot exhaust process memory or block monitoring. `discovery_bootstrap::LoggingConfig`'s
/// default level was *also* changed (`"info"` → `"info,sqlx=warn"`) so console/file stay
/// quiet by default too, but that alone wouldn't have closed the loop for an operator who
/// explicitly configures a broader `level` — hence the hardcoded exclusion here, which no
/// configuration can accidentally (or even deliberately) reopen.
pub fn init(
    config: &LoggingConfig,
) -> (
    Arc<LogBuffer>,
    tokio::sync::mpsc::Receiver<LogEntry>,
    Option<tracing_appender::non_blocking::WorkerGuard>,
) {
    let log_buffer = Arc::new(LogBuffer::new(config.buffer_size));
    const PERSIST_QUEUE_CAPACITY: usize = 8192;
    let (persist_tx, persist_rx) = tokio::sync::mpsc::channel(PERSIST_QUEUE_CAPACITY);

    let console_layer =
        tracing_subscriber::fmt::layer().with_filter(parse_filter(&config.console_filter()));
    let dashboard_layer = BufferLayer::new(log_buffer.clone())
        .with_filter(parse_filter(&without_sqlx(&config.dashboard_filter())));
    let persisting_layer = PersistingLayer::new(persist_tx)
        .with_filter(parse_filter(&without_sqlx(&config.file_filter())));

    let mut guard = None;
    let file_layer = (!config.file.trim().is_empty()).then(|| {
        let path = std::path::PathBuf::from(&config.file);
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let prefix = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("discovery.log")
            .to_string();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "warning: could not create log directory {}: {e}",
                dir.display()
            );
        }
        let rotation = match config.file_rotation.as_str() {
            "hourly" => tracing_appender::rolling::Rotation::HOURLY,
            "never" => tracing_appender::rolling::Rotation::NEVER,
            _ => tracing_appender::rolling::Rotation::DAILY,
        };
        let appender = tracing_appender::rolling::RollingFileAppender::new(rotation, &dir, &prefix);
        let (non_blocking, worker_guard) = tracing_appender::non_blocking(appender);
        guard = Some(worker_guard);
        tracing_subscriber::fmt::layer()
            .with_writer(non_blocking)
            .with_ansi(false)
            .with_filter(parse_filter(&config.file_filter()))
    });

    tracing_subscriber::registry()
        .with(console_layer)
        .with(dashboard_layer)
        .with(file_layer)
        .with(persisting_layer)
        .init();

    (log_buffer, persist_rx, guard)
}

fn parse_filter(directives: &str) -> EnvFilter {
    EnvFilter::try_new(directives).unwrap_or_else(|e| {
        eprintln!("warning: invalid log filter '{directives}' ({e}), falling back to 'info'");
        EnvFilter::new("info")
    })
}

/// Appends an unconditional `sqlx=off` to `directives` — a target-scoped directive always
/// wins over a less-specific one regardless of order (`tracing_subscriber::EnvFilter`'s
/// own matching rule), so this reliably suppresses `sqlx::*` even if `directives` itself
/// already grants it a level (e.g. an operator-set `level = "trace"`). See `init`'s docs
/// for why `dashboard_layer`/`persisting_layer` specifically must never see these events.
fn without_sqlx(directives: &str) -> String {
    format!("{directives},sqlx=off")
}
