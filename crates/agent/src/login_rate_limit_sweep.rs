use std::sync::Arc;
use std::time::Duration;

use discovery_web::LoginRateLimiter;

/// Periodically evicts stale `(username, ip)` buckets from `limiter` — see
/// `discovery_web::LoginRateLimiter`'s docs for why this is needed (unlike the trap/syslog
/// per-IP maps this project accepts as never-evicting, `username` here is attacker-
/// controlled free text, not IP-bounded). Singleton, process-wide loop: there is exactly one
/// `LoginRateLimiter` per process, no per-key `ActiveChains` guard needed. Lives here, not
/// in `discovery-web` alongside the limiter
/// itself, matching how every other recurring loop in this project lives in
/// `discovery-agent` regardless of which crate owns the state being swept.
pub async fn run_login_rate_limiter_sweep_loop(
    limiter: Arc<LoginRateLimiter>,
    sweep_interval_secs: u64,
    stale_after_secs: u64,
) {
    let interval = Duration::from_secs(sweep_interval_secs.max(1));
    let stale_after = Duration::from_secs(stale_after_secs.max(1));
    loop {
        // ~10% jitter, same convention as this project's other recurring loops.
        let jitter_ms = {
            use rand::Rng;
            rand::thread_rng().gen_range(0..=(interval.as_millis() / 10).max(1) as u64)
        };
        tokio::time::sleep(interval + Duration::from_millis(jitter_ms)).await;
        limiter.sweep_stale(stale_after);
    }
}
