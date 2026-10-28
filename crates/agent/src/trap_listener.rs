//! SNMP Trap UDP receive loop — owns the `discovery-snmp::TrapListener`, the bounded
//! in-memory ingest worker pool that consumes it, and the rebuild-on-SNMPv3-credential-
//! change orchestration `docs/Changelog/2026-08-30 - SNMP Trap.md` settled on (accepted
//! caveat: USM users are keyed by username alone, not per-device — see that changelog and
//! `discovery-snmp::TrapUsmUser`'s docs).
//!
//! Nothing here touches the `jobs` SQL queue for the high-frequency receive path — only
//! [`crate::trap_ingest::ingest_one`]'s own `AlertEval` enqueue at the very end does, same
//! reasoning as `SnmpTrapConfig`'s docs (`discovery-bootstrap`) give for
//! `ingest_concurrency` being a plain in-memory worker pool, not a `QueueKind`.
use discovery_bootstrap::SnmpTrapConfig;
use discovery_config_store::SettingsStore;
use discovery_core::{SnmpAuth, TrapEngineState};
use discovery_devices::DeviceStore;
use discovery_snmp::{
    build_trap_receiver, AuthoritativeEngine, PersistedAuthoritativeEngine, TrapListener,
    TrapUsmUser,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::trap_ingest::{ingest_one, TrapIngestState};

/// How often the supervisor loop checks whether the fleet's known SNMPv3 trap usernames
/// changed while otherwise just forwarding received packets — a rebuild only actually
/// happens when the *set itself* changed, not on this cadence unconditionally. Not
/// user-configurable: this is purely an internal responsiveness/overhead trade-off, not a
/// behavior a deployment would ever need to tune.
const V3_USER_REFRESH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

fn boxed_err<E: std::fmt::Display>(e: E) -> Box<dyn std::error::Error + Send + Sync> {
    e.to_string().into()
}

/// Every distinct SNMPv3 username currently configured across the fleet, with whichever
/// device's credentials were seen last for that username winning if more than one device
/// shares a name (see this module's docs on the username-not-per-device caveat) — sorted
/// by username so [`fingerprint_users`] is stable regardless of `DeviceStore::all`'s
/// iteration order.
async fn collect_v3_users(devices: &dyn DeviceStore) -> anyhow::Result<Vec<TrapUsmUser>> {
    let mut by_username = std::collections::BTreeMap::new();
    for device in devices.all().await? {
        if let Some(creds) = &device.snmp_credentials {
            if let SnmpAuth::UsmV3(v3) = &creds.auth {
                by_username.insert(v3.user.clone(), v3.clone());
            }
        }
    }
    Ok(by_username
        .into_iter()
        .map(|(username, credentials)| TrapUsmUser {
            username,
            credentials,
        })
        .collect())
}

/// Cheap equality check for "did the known-user set actually change" — usernames alone;
/// a password/protocol-only change on an existing username is deliberately *not* detected
/// here as a distinct fingerprint (it would need a full credential comparison), so it only
/// takes effect on the *next* rebuild triggered by some other add/remove. Acceptable: v3
/// trap credentials changing without any device add/remove is rare, and the receiver still
/// works correctly with the stale password in the meantime — it just won't authenticate
/// traps from that device until the next rebuild, the same "eventually consistent" story
/// `discovery-agent`'s hot-reload paths already tell elsewhere (e.g. `profile_reload`).
fn fingerprint_users(users: &[TrapUsmUser]) -> BTreeSet<String> {
    users.iter().map(|u| u.username.clone()).collect()
}

async fn load_or_install_engine(
    settings: Arc<dyn SettingsStore>,
) -> anyhow::Result<AuthoritativeEngine> {
    let existing = settings.get_trap_engine_state().await?;
    let persist = move |persisted: &PersistedAuthoritativeEngine| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = TrapEngineState { engine_id: persisted.engine_id().to_vec(), engine_boots: persisted.engine_boots() };
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(settings.set_trap_engine_state(&state))).map_err(boxed_err)
    };
    match existing {
        Some(state) => {
            let persisted = PersistedAuthoritativeEngine::new(state.engine_id, state.engine_boots)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(AuthoritativeEngine::restart(persisted, persist)
                .map_err(|e| anyhow::anyhow!("{e}"))?)
        }
        None => {
            let engine_id =
                discovery_snmp::generate_engine_id().map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(AuthoritativeEngine::install(engine_id.to_vec(), persist)
                .map_err(|e| anyhow::anyhow!("{e}"))?)
        }
    }
}

async fn build_listener(
    config: &SnmpTrapConfig,
    settings: &Arc<dyn SettingsStore>,
    v3_users: &[TrapUsmUser],
) -> anyhow::Result<TrapListener> {
    let engine = if v3_users.is_empty() {
        None
    } else {
        Some(load_or_install_engine(settings.clone()).await?)
    };
    build_trap_receiver(&config.bind_addr, engine, v3_users).await
}

/// Entry point — spawned once at startup if `config.enabled`, runs until the process
/// exits. A build/rebuild failure is fatal to this task (logged, task ends) rather than
/// retried in a tight loop — the same "don't spin on a config problem" posture as any
/// other startup-time misconfiguration in this project; fixing it needs a restart (or,
/// once the v3 credential set next changes, another rebuild attempt).
pub async fn run_trap_listener(
    config: SnmpTrapConfig,
    settings: Arc<dyn SettingsStore>,
    ingest_state: Arc<TrapIngestState>,
) {
    if !config.enabled {
        return;
    }
    // Ingress ACL (SEC-19) — parsed once, not per packet or per rebuild; `config` is
    // immutable for the lifetime of this task (no hot-reload for this section), same
    // "fixing it needs a restart" posture the rest of this function's docs already state.
    let allowed_sources = match config.compiled_allowed_sources() {
        Ok(allowed) => allowed,
        Err(e) => {
            warn!(error = %e, "trap listener: failed to parse allowed_sources — not retried, requires a restart");
            return;
        }
    };

    // Do not discard accepted traps when SQLite or alert evaluation temporarily slows
    // workers. A bounded hand-off with an awaited send keeps that no-internal-drop
    // contract while preventing a stalled store from growing process memory without limit.
    const INGEST_QUEUE_CAPACITY: usize = 1024;
    let (tx, rx) = mpsc::channel(INGEST_QUEUE_CAPACITY);
    // Fan-out to `ingest_concurrency` parallel `ingest_one` calls without a manual
    // work-stealing pool: `spawn_ingest_workers` wraps the single mpsc receiver in a
    // shared mutex and spawns that many tasks all pulling from it — whichever task is
    // free wins the next item, tokio's mpsc doesn't need more than that to fan out.
    spawn_ingest_workers(rx, ingest_state.clone(), config.ingest_concurrency.max(1));

    loop {
        let v3_users = match collect_v3_users(&*ingest_state.devices).await {
            Ok(users) => users,
            Err(e) => {
                warn!(error = %e, "trap listener: failed to enumerate SNMPv3 trap users, retrying shortly");
                tokio::time::sleep(V3_USER_REFRESH_CHECK_INTERVAL).await;
                continue;
            }
        };
        let mut active_fingerprint = fingerprint_users(&v3_users);

        let listener = match build_listener(&config, &settings, &v3_users).await {
            Ok(listener) => listener,
            Err(e) => {
                warn!(error = %e, "trap listener: failed to build/rebuild receiver, retrying shortly");
                tokio::time::sleep(V3_USER_REFRESH_CHECK_INTERVAL).await;
                continue;
            }
        };
        info!(bind_addr = %listener.local_addr(), v3_users = v3_users.len(), "SNMP trap listener (re)built");

        loop {
            tokio::select! {
                received = listener.recv() => {
                    match received {
                        Ok(trap) => {
                            // Ingress ACL (SEC-19) before the rate limiter — same
                            // reasoning as `run_syslog_listener`'s docs: an unlisted
                            // source shouldn't consume rate-limit budget either.
                            if !allowed_sources.contains(trap.source.ip()) {
                                debug!(source = %trap.source.ip(), "trap listener: dropping packet from a source not in allowed_sources");
                                continue;
                            }
                            if !ingest_state.check_rate_limit(trap.source.ip()) {
                                continue;
                            }
                            if tx.send(trap).await.is_err() {
                                warn!("trap ingest workers stopped — dropping a packet");
                                return;
                            }
                        }
                        Err(e) => warn!(error = %e, "trap listener: receive error"),
                    }
                }
                _ = tokio::time::sleep(V3_USER_REFRESH_CHECK_INTERVAL) => {
                    let fresh_users = match collect_v3_users(&*ingest_state.devices).await {
                        Ok(users) => users,
                        Err(e) => {
                            warn!(error = %e, "trap listener: failed to re-check SNMPv3 trap users this cycle");
                            continue;
                        }
                    };
                    let fresh_fingerprint = fingerprint_users(&fresh_users);
                    if fresh_fingerprint != active_fingerprint {
                        info!("trap listener: SNMPv3 trap user set changed — rebuilding receiver");
                        active_fingerprint = fresh_fingerprint;
                        break;
                    }
                }
            }
        }
    }
}

fn spawn_ingest_workers(
    rx: mpsc::Receiver<discovery_snmp::DecodedTrap>,
    state: Arc<TrapIngestState>,
    concurrency: usize,
) {
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    for _ in 0..concurrency {
        let rx = rx.clone();
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                let trap = {
                    let mut guard = rx.lock().await;
                    guard.recv().await
                };
                let Some(trap) = trap else { break }; // channel closed — sender dropped
                if let Err(e) = ingest_one(&state, trap).await {
                    warn!(error = %e, "trap ingest failed for one packet");
                }
            }
        });
    }
}
