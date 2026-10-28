use dashmap::DashSet;
use std::hash::Hash;

/// Tracks which keys *this process* has already started a recurring chain for — generic
/// over the key type so the same small utility covers both "which devices have an active
/// `MetricPoll` chain" (keyed by device `Uuid`, see `ProfileApplyHandler`) and "which IPs
/// have an active `SnmpPoll` identity chain" (keyed by IP string, see `DiscoveryHandler`).
///
/// Purely in-memory and process-local, on purpose: its only job is to answer "is there
/// already a chain running for this key in the current process". That correctly starts
/// out empty on every process start — including after a crash/restart — which is exactly
/// what's needed: any chain a *previous* process had running died with it (it was just a
/// `tokio::spawn` + sleep, never persisted), so a fresh process has to be willing to start
/// one again for a key it's never personally seen before, even if that key is old news to
/// the system as a whole. Found by actually restarting the agent against a real Postgres
/// and watching metric polling silently stop — see `discovery/CLAUDE.md`.
///
/// Moved here from `discovery-agent` 2026-08-21 (was `discovery_agent::active_chains`) so
/// `discovery-web` can also hold a reference and call [`Self::remove`] when a device is
/// deleted — see that method's docs for the bug this fixes. `discovery-core` is the shared
/// vocabulary crate both `discovery-agent` and `discovery-web` already depend on, avoiding
/// a new cross-dependency between the two (same reasoning as `discovery_core::Domain`'s
/// docs for its own 2026-08-21 move).
pub struct ActiveChains<K: Eq + Hash>(DashSet<K>);

// Not `#[derive(Default)]`: the derive macro adds a `K: Default` bound on the *type*
// (visible on `ActiveChains<K>` itself, forcing every caller — even ones that never touch
// `default()` — to prove `K: Default`), even though `DashSet<K>: Default` only actually
// needs `K: Eq + Hash`. A hand-written impl keeps the bound where it belongs.
impl<K: Eq + Hash> Default for ActiveChains<K> {
    fn default() -> Self {
        Self(DashSet::new())
    }
}

impl<K: Eq + Hash> ActiveChains<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks `key` as having an active chain in this process. Returns `true` the first
    /// time it's called for a given `key` in this process's lifetime ("you need to
    /// actually start one"), `false` on every subsequent call ("one's already running,
    /// don't start a second").
    pub fn mark(&self, key: K) -> bool {
        self.0.insert(key)
    }

    /// Non-mutating peek — added 2026-08-18 for `DiscoveryHandler`'s dead-device gate
    /// (`SubnetSpec::create_dead_devices`): it needs to know "is there already a chain for
    /// this IP" as a *cheap fast path that skips the ping check entirely* for already-known
    /// devices, without that check itself counting as "starting" one — `mark` can't be
    /// reused for this since calling it would permanently consume the key even when the
    /// caller ends up deciding not to start anything.
    pub fn contains(&self, key: &K) -> bool {
        self.0.contains(key)
    }

    /// Forgets `key` — added 2026-08-21, scale/correctness audit finding: without this,
    /// every mark made here was permanent for the life of the process, which is two
    /// problems at once. (1) Unbounded memory growth: nothing ever shrinks these sets, so a
    /// process that discovers-then-deletes devices over a long uptime keeps every deleted
    /// device's key forever. (2) A real correctness bug, not just a leak: `contains`/`mark`
    /// checks (`DiscoveryHandler`'s dead-device gate, `ProfileApplyHandler`'s "already
    /// polling" gate) would permanently refuse to ever start a fresh chain for a key that
    /// belonged to a device the operator explicitly deleted — including an IP address a
    /// DHCP network hands to a completely different physical device later. Callers must
    /// remove a device's keys (`device_id` from `active_chains`/`reachability_chains`, `ip`
    /// from `identity_chains`) at the point of deletion — see `discovery-web::delete_device`
    /// and `discovery-agent::dead_device_cleanup`.
    pub fn remove(&self, key: &K) {
        self.0.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn mark_is_true_only_the_first_time_per_key() {
        let chains: ActiveChains<Uuid> = ActiveChains::new();
        let id = Uuid::new_v4();
        assert!(chains.mark(id));
        assert!(!chains.mark(id));
        assert!(!chains.mark(id));
    }

    #[test]
    fn different_keys_are_tracked_independently() {
        let chains: ActiveChains<Uuid> = ActiveChains::new();
        assert!(chains.mark(Uuid::new_v4()));
        assert!(chains.mark(Uuid::new_v4()));
    }

    #[test]
    fn works_with_string_keys_too() {
        let chains: ActiveChains<String> = ActiveChains::new();
        assert!(chains.mark("10.0.0.1".to_string()));
        assert!(!chains.mark("10.0.0.1".to_string()));
        assert!(chains.mark("10.0.0.2".to_string()));
    }

    #[test]
    fn remove_lets_the_key_be_marked_again() {
        let chains: ActiveChains<Uuid> = ActiveChains::new();
        let id = Uuid::new_v4();
        assert!(chains.mark(id));
        assert!(!chains.mark(id), "already marked — must not re-mark yet");
        chains.remove(&id);
        assert!(
            chains.mark(id),
            "after remove, the key must be markable again as if fresh"
        );
    }

    #[test]
    fn remove_on_a_never_marked_key_is_a_harmless_no_op() {
        let chains: ActiveChains<Uuid> = ActiveChains::new();
        chains.remove(&Uuid::new_v4());
        // Must not panic — that's the whole assertion.
    }
}
