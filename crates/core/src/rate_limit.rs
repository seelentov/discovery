//! Generic per-key rate limiter — continuous-refill token bucket. Originally lived in
//! `discovery-agent::rate_limit` for the SNMP-trap/syslog push-ingestion pipelines
//! (per-source-IP); promoted here (2026-09-12, security audit finding:
//! `/api/auth/login` had zero brute-force protection) so `discovery-web`'s login endpoint
//! could reuse the same primitive instead of a second implementation — `discovery-web`
//! can't depend on `discovery-agent` (the dependency runs the other way, agent -> web), so
//! this shared-vocabulary crate is the only place both sides can reach.

/// A bucket refills at `rate_per_sec` tokens/sec (fractional rates allowed — e.g. `1.0/60.0`
/// for "one recovered attempt per minute"), capped at the capacity fixed by [`Self::new`].
///
/// The cap is intentionally derived from the bucket's own stored `capacity`, not from
/// whatever `rate_per_sec` a given [`Self::try_consume`] call happens to pass. An earlier
/// version capped at `rate_per_sec` itself, which silently collapsed any real burst
/// allowance to that rate the instant the first call ran (since refill on the very first
/// call is ~0, then immediately `.min(rate_per_sec)`). Every pre-existing caller (SNMP trap
/// and syslog ingestion) always happens to pass the same value to both `new()` and every
/// `try_consume()` call, so that bug was invisible to them and this fix is behavior-
/// preserving (see `token_bucket_allows_bursts_up_to_capacity_then_blocks` below, unchanged).
/// It needed fixing for the login limiter, which genuinely wants "burst of N immediate
/// attempts, then a much slower trickle" — two different numbers.
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32) -> Self {
        Self {
            tokens: capacity as f64,
            capacity: capacity as f64,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Refills continuously (not "one bucket per wall-clock second") so a burst right after
    /// a quiet stretch isn't unfairly capped by where the second happened to start.
    pub fn try_consume(&mut self, rate_per_sec: f64) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * rate_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// When this bucket was last touched by [`Self::try_consume`] (or created, if never
    /// consumed since). Exists so a caller holding many keyed buckets (e.g.
    /// `discovery_web::LoginRateLimiter`) can evict entries idle longer than some threshold
    /// without this crate needing to know anything about eviction policy itself — continuous
    /// refill already means an untouched-long-enough bucket is back at full capacity, so
    /// evicting it changes nothing observable, only reclaims memory.
    pub fn last_refill(&self) -> std::time::Instant {
        self.last_refill
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_bursts_up_to_capacity_then_blocks() {
        let mut bucket = TokenBucket::new(3);
        assert!(bucket.try_consume(3.0));
        assert!(bucket.try_consume(3.0));
        assert!(bucket.try_consume(3.0));
        assert!(
            !bucket.try_consume(3.0),
            "fourth consume within the same instant must be rejected"
        );
    }

    #[test]
    fn capacity_is_fixed_at_construction_not_reset_by_a_smaller_rate_argument() {
        // Regression test for the bug this module's docs describe: a burst of 5 must survive
        // even though every `try_consume` call passes a rate far below that capacity.
        let mut bucket = TokenBucket::new(5);
        for _ in 0..5 {
            assert!(bucket.try_consume(1.0 / 60.0));
        }
        assert!(
            !bucket.try_consume(1.0 / 60.0),
            "burst of 5 must be exhausted after exactly 5 consumes"
        );
    }

    #[test]
    fn token_bucket_refills_over_time_at_configured_rate() {
        // A fast rate + a short real sleep proves refill-over-time without a slow/flaky test.
        let mut bucket = TokenBucket::new(1);
        assert!(bucket.try_consume(1000.0));
        assert!(
            !bucket.try_consume(1000.0),
            "no tokens left immediately after consuming the only one"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(
            bucket.try_consume(1000.0),
            "1000/sec refill should have replenished the bucket after 5ms"
        );
    }

    #[test]
    fn last_refill_advances_on_every_consume_not_just_at_construction() {
        let mut bucket = TokenBucket::new(5);
        let at_construction = bucket.last_refill();
        std::thread::sleep(std::time::Duration::from_millis(5));
        bucket.try_consume(1.0);
        assert!(bucket.last_refill() > at_construction, "last_refill must move forward on use -- callers (e.g. discovery_web::LoginRateLimiter's sweep) rely on this to tell an active bucket apart from an idle one");
    }
}
