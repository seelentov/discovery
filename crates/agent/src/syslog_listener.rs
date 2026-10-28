//! Syslog UDP receive loop — owns the `discovery-agent::syslog_decode::SyslogListener` and
//! the bounded in-memory ingest worker pool that consumes it. Much simpler than
//! `trap_listener.rs`: no USM/engine-identity rebuild orchestration, because syslog has no
//! protocol-level authentication to register users for at all (see
//! `crate::syslog_ingest`'s docs) — the listener is bound exactly once at startup and never
//! rebuilt.
use discovery_bootstrap::SyslogConfig;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::syslog_decode::{DecodedSyslogMessage, SyslogListener};
use crate::syslog_ingest::{ingest_one, SyslogIngestState};

/// Entry point — spawned once at startup if `config.enabled`, runs until the process
/// exits. A bind failure is fatal to this task (logged, task ends) rather than retried in a
/// tight loop — same "don't spin on a config problem" posture as `run_trap_listener`;
/// fixing it needs a restart.
pub async fn run_syslog_listener(config: SyslogConfig, ingest_state: Arc<SyslogIngestState>) {
    if !config.enabled {
        return;
    }

    let allowed_sources = match config.compiled_allowed_sources() {
        Ok(allowed) => allowed,
        Err(e) => {
            warn!(error = %e, "syslog listener: failed to parse allowed_sources — not retried, requires a restart");
            return;
        }
    };
    let listener = match SyslogListener::bind(&config.bind_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            warn!(error = %e, bind_addr = %config.bind_addr, "syslog listener: failed to bind — not retried, requires a restart");
            return;
        }
    };
    info!(bind_addr = ?listener.local_addr().ok(), "syslog listener started");

    // The receive path must not discard an already accepted UDP datagram merely because
    // workers are temporarily behind. A bounded hand-off with an awaited send preserves
    // that contract without allowing a stalled store to grow process memory without limit.
    const INGEST_QUEUE_CAPACITY: usize = 1024;
    let (tx, rx) = mpsc::channel(INGEST_QUEUE_CAPACITY);
    spawn_ingest_workers(rx, ingest_state.clone(), config.ingest_concurrency.max(1));

    loop {
        match listener.recv().await {
            Ok(message) => {
                // Ingress ACL (SEC-19) before the rate limiter — an unlisted source
                // shouldn't consume any of the per-source token bucket's budget, and
                // definitely shouldn't reach `ingest_one`.
                if !allowed_sources.contains(message.source.ip()) {
                    debug!(source = %message.source.ip(), "syslog listener: dropping packet from a source not in allowed_sources");
                    continue;
                }
                if !ingest_state.check_rate_limit(message.source.ip()) {
                    continue;
                }
                if tx.send(message).await.is_err() {
                    warn!("syslog ingest workers stopped — dropping a packet");
                    return;
                }
            }
            Err(e) => warn!(error = %e, "syslog listener: receive error"),
        }
    }
}

fn spawn_ingest_workers(
    rx: mpsc::Receiver<DecodedSyslogMessage>,
    state: Arc<SyslogIngestState>,
    concurrency: usize,
) {
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    for _ in 0..concurrency {
        let rx = rx.clone();
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                let message = {
                    let mut guard = rx.lock().await;
                    guard.recv().await
                };
                let Some(message) = message else { break }; // channel closed — sender dropped
                if let Err(e) = ingest_one(&state, message).await {
                    warn!(error = %e, "syslog ingest failed for one packet");
                }
            }
        });
    }
}
