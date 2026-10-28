//! IPv4 CIDR/netmask math and the "enumerate a `DiscoveryConfig`'s subnets and enqueue a
//! `Discovery` job for every host address" action — split out of `discovery-agent` so both
//! the scheduled scan loop (`discovery-agent::discovery_scan::run_discovery_schedule_loop`)
//! and the dashboard's manual "run now" button (`discovery-web`, `POST
//! /api/discovery-configs/:name/run`) can share the exact same enumeration/enqueue logic
//! without `discovery-web` having to depend on `discovery-agent` (which would be circular
//! — `discovery-agent` already depends on `discovery-web` to serve the dashboard).

use std::net::Ipv4Addr;
use std::sync::Arc;

use discovery_core::payload::DiscoveryPayload;
use discovery_core::QueueKind;
use discovery_queue::JobQueueStore;
use tracing::warn;

use crate::{DiscoveryConfig, SubnetSpec};

/// Sanity cap on how many addresses a single configured subnet may expand to (65536 = a
/// /16) — a fat-fingered `mask = "255.0.0.0"` would otherwise try to enqueue 16 million
/// `Discovery` jobs. Oversized entries are skipped (with a warning), not truncated —
/// silently scanning *part* of a typo'd range would be more confusing than refusing it.
const MAX_SUBNET_SIZE: u64 = 65_536;

/// Converts a dotted-decimal subnet mask (`"255.255.255.0"`) to a CIDR prefix length,
/// rejecting anything that isn't a contiguous run of 1-bits followed by 0-bits (the only
/// thing a "mask" can validly mean). `"0.0.0.0"` (prefix `/0`, "match everything") is a
/// valid mask — found live via `SubnetTarget::validate` (TASK-20260921-017): `ones == 0`
/// means `32 - ones == 32`, and `<< 32` on a `u32` is a shift-by-bit-width, which panics
/// under debug assertions (and is unspecified, not simply zero, in release) — the old
/// `if ones == 32 { u32::MAX } else { ... }` branch only guarded the *other* edge, leaving
/// this one live for any caller (this crate's own `matches`/`matches_device` included).
pub(crate) fn mask_to_prefix_len(mask: &str) -> anyhow::Result<u32> {
    let addr: Ipv4Addr = mask
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid subnet mask '{mask}': {e}"))?;
    let bits = u32::from(addr);
    let ones = bits.leading_ones();
    let expected = if ones == 0 { 0 } else { !0u32 << (32 - ones) };
    anyhow::ensure!(
        bits == expected,
        "invalid subnet mask '{mask}': bits are not a contiguous run of 1s followed by 0s"
    );
    Ok(ones)
}

/// Enumerates every host address in an IPv4 network, excluding the network and broadcast
/// addresses (for `/31`/`/32`, where that distinction doesn't apply, every address is
/// included — RFC 3021 point-to-point links and single hosts). Rejects the range outright
/// (rather than silently truncating it) if it would expand past [`MAX_SUBNET_SIZE`].
pub fn enumerate_ipv4_hosts(ip: &str, mask: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
    let base: Ipv4Addr = ip
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid subnet ip '{ip}': {e}"))?;
    let prefix = mask_to_prefix_len(mask)?;

    let host_bits = 32 - prefix;
    let num_addresses: u64 = 1u64 << host_bits;
    anyhow::ensure!(
        num_addresses <= MAX_SUBNET_SIZE,
        "subnet {ip}/{prefix} expands to {num_addresses} addresses, over the {MAX_SUBNET_SIZE} cap — split it into smaller ranges"
    );

    let base_u32 = u32::from(base);
    let network_u32 = if host_bits == 32 {
        0
    } else {
        base_u32 & (!0u32 << host_bits)
    };

    let (first_offset, last_offset) = if host_bits <= 1 {
        (0u64, num_addresses.saturating_sub(1))
    } else {
        (1u64, num_addresses - 2)
    };

    Ok((first_offset..=last_offset)
        .map(|offset| Ipv4Addr::from(network_u32.wrapping_add(offset as u32)))
        .collect())
}

/// Does `candidate` fall inside the network described by `ip`/`mask`?
///
/// `pub(crate)`, not private — reused by `maintenance_window`'s selector matching
/// (`MaintenanceWindow::matches`), which needs the exact same dotted-decimal ip+mask math
/// this module already has, not a second copy of it.
pub(crate) fn ipv4_in_subnet(candidate: Ipv4Addr, ip: &str, mask: &str) -> anyhow::Result<bool> {
    let network: Ipv4Addr = ip
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid subnet ip '{ip}': {e}"))?;
    let prefix = mask_to_prefix_len(mask)?;
    let host_bits = 32 - prefix;
    let masked = |addr: Ipv4Addr| {
        if host_bits == 32 {
            0
        } else {
            u32::from(addr) & (!0u32 << host_bits)
        }
    };
    Ok(masked(network) == masked(candidate))
}

/// Finds the first config's subnet that `ip` falls inside, if any — used to look up which
/// SNMP version/community/port/timeout candidates, enrichment OIDs/labels, and
/// `create_dead_devices` policy apply to it.
///
/// **Does not filter by `config.enabled` (bug found live 2026-08-18, direct user report:**
/// "Так же я сейчас вижу опять что создались девайсы под все ipшники, несмотря на флаг не
/// создавать мертвые девайсы"). It used to, on the theory that a disabled config's
/// subnets shouldn't apply to anything — but `POST /api/discovery-configs/:name/run`
/// (the manual "run now" button) deliberately enqueues a disabled config's candidates
/// anyway (see `discovery/README.md`'s "сознательно игнорирует `config.enabled`" — explicit
/// click, explicit intent). Every one of those candidates then hit *this* function from
/// `DiscoveryHandler`/`SnmpPollHandler`/`ReachabilityPollHandler`, got `None` back because
/// their owning config was still `enabled = false`, and silently fell back to each call
/// site's own default: `create_dead_devices` defaulted to `true` (its "no matching subnet"
/// fallback — see `DiscoveryHandler`'s docs), completely bypassing the dead-device gate,
/// and `SnmpPollHandler` had no versions/communities to negotiate with at all, so **not one
/// device — including genuinely live ones — ever got SNMP credentials**. `enabled` only
/// controls whether [`crate::discovery_config::DiscoveryConfig`]'s schedule is allowed to
/// *automatically* fire (`discovery_agent::discovery_scan::run_discovery_schedule_loop`
/// checks it directly, independently of this function) — it says nothing about whether a
/// candidate IP that's already an enqueued `Discovery` job (manually triggered or not)
/// should still be treated as belonging to its subnet.
pub fn find_subnet_spec_for_ip(configs: &[DiscoveryConfig], ip: &str) -> Option<SubnetSpec> {
    let candidate: Ipv4Addr = ip.parse().ok()?;
    configs
        .iter()
        .flat_map(|c| &c.subnets)
        .find(|subnet| ipv4_in_subnet(candidate, &subnet.ip, &subnet.mask).unwrap_or(false))
        .cloned()
}

/// How many `enqueue` calls [`enqueue_scan`] keeps in flight at once — added 2026-08-21,
/// scale audit finding: this used to await one `enqueue` at a time, so a config with
/// several large subnets (each up to [`MAX_SUBNET_SIZE`] addresses) held the calling HTTP
/// request (`POST /api/discovery-configs/:name/run`) open for the sum of hundreds of
/// thousands of sequential round trips. Bounded, not unbounded, concurrency — firing all
/// of them at once would itself be the kind of enqueue burst
/// [`discovery_core::ActiveChains`]'s docs and the jitter added to
/// `discovery-agent::handlers`'s reschedule loops exist to avoid; 64 in flight is enough to
/// stop being round-trip-latency-bound without turning this into its own thundering herd.
const MAX_CONCURRENT_ENQUEUES: usize = 64;

/// Enumerates every subnet in `config` and enqueues a `Discovery` job for each host
/// address — the actual work behind both a schedule firing and a manual "run now" click.
/// Returns how many candidates were enqueued (for the caller to report back, e.g. in an
/// API response or a log line).
pub async fn enqueue_scan(config: &DiscoveryConfig, store: &Arc<dyn JobQueueStore>) -> usize {
    let mut enqueued = 0usize;
    let mut in_flight = tokio::task::JoinSet::new();
    for subnet in &config.subnets {
        match enumerate_ipv4_hosts(&subnet.ip, &subnet.mask) {
            Ok(addrs) => {
                for addr in addrs {
                    if in_flight.len() >= MAX_CONCURRENT_ENQUEUES {
                        if let Some(Ok(ok)) = in_flight.join_next().await {
                            enqueued += ok as usize;
                        }
                    }
                    let ip = addr.to_string();
                    let Ok(payload) = serde_json::to_value(DiscoveryPayload { ip: ip.clone() })
                    else {
                        continue;
                    };
                    let store = store.clone();
                    let config_name = config.name.clone();
                    in_flight.spawn(async move {
                        match store.enqueue(QueueKind::Discovery, payload, Some(&ip)).await {
                            Ok(_) => true,
                            Err(e) => {
                                warn!(config = %config_name, error = %e, ip = %ip, "failed to enqueue candidate IP");
                                false
                            }
                        }
                    });
                }
            }
            Err(e) => {
                warn!(config = %config.name, subnet_ip = %subnet.ip, error = %e, "skipping invalid or oversized subnet")
            }
        }
    }
    while let Some(result) = in_flight.join_next().await {
        if let Ok(ok) = result {
            enqueued += ok as usize;
        }
    }
    enqueued
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_24_excludes_network_and_broadcast() {
        let addrs = enumerate_ipv4_hosts("10.0.0.0", "255.255.255.0").unwrap();
        assert_eq!(addrs.len(), 254);
        assert_eq!(addrs.first(), Some(&"10.0.0.1".parse().unwrap()));
        assert_eq!(addrs.last(), Some(&"10.0.0.254".parse().unwrap()));
    }

    #[test]
    fn slash_32_is_exactly_one_address() {
        let addrs = enumerate_ipv4_hosts("10.0.0.5", "255.255.255.255").unwrap();
        assert_eq!(addrs, vec!["10.0.0.5".parse::<Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn oversized_subnet_is_rejected_not_truncated() {
        assert!(enumerate_ipv4_hosts("10.0.0.0", "255.0.0.0").is_err()); // /8, ~16M addresses
    }

    #[test]
    fn non_contiguous_mask_is_rejected() {
        assert!(mask_to_prefix_len("255.0.255.0").is_err());
    }

    /// TASK-20260921-017 — `0.0.0.0` (prefix `/0`) used to panic ("attempt to shift left
    /// with overflow" under debug assertions) instead of returning `Ok(0)`: `leading_ones()
    /// == 0` meant the `!0u32 << (32 - ones)` branch shifted by a full 32 bits, which is
    /// out of range for a `u32`.
    #[test]
    fn all_zero_mask_is_a_valid_slash_zero_not_a_panic() {
        assert_eq!(mask_to_prefix_len("0.0.0.0").unwrap(), 0);
    }

    #[test]
    fn all_ones_mask_is_a_valid_slash_32() {
        assert_eq!(mask_to_prefix_len("255.255.255.255").unwrap(), 32);
    }

    #[test]
    fn ip_in_subnet_matches_only_addresses_inside_the_network() {
        let inside: Ipv4Addr = "10.0.0.42".parse().unwrap();
        let outside: Ipv4Addr = "10.0.1.42".parse().unwrap();
        assert!(ipv4_in_subnet(inside, "10.0.0.0", "255.255.255.0").unwrap());
        assert!(!ipv4_in_subnet(outside, "10.0.0.0", "255.255.255.0").unwrap());
    }

    /// Regression test for the live bug found 2026-08-18 (see `find_subnet_spec_for_ip`'s
    /// docs) — a disabled config's subnet metadata must still be found, because a manual
    /// "run now" deliberately enqueues candidates from a disabled config, and every one of
    /// them needs its subnet's `create_dead_devices`/SNMP settings honored downstream.
    #[test]
    fn find_subnet_spec_still_applies_even_when_the_owning_config_is_disabled() {
        use crate::Schedule;
        let config = DiscoveryConfig {
            name: "test".into(),
            enabled: false,
            schedule: Schedule::Calendar {
                months: vec![],
                days_of_month: vec![],
                time: chrono::NaiveTime::from_hms_opt(3, 0, 0).unwrap(),
            },
            subnets: vec![SubnetSpec {
                ip: "10.0.0.0".into(),
                mask: "255.255.255.0".into(),
                port: 161,
                credentials: vec![],
                oids: Default::default(),
                labels: Default::default(),
                snmp_timeout_ms: None,
                snmp_retries: None,
                create_dead_devices: true,
            }],
        };
        let found = find_subnet_spec_for_ip(&[config], "10.0.0.5");
        assert!(found.is_some(), "disabled != irrelevant — a manually-triggered candidate from this config still needs its subnet settings");
        assert!(found.unwrap().create_dead_devices);
    }

    #[test]
    fn find_subnet_spec_still_returns_none_for_an_ip_outside_every_configured_subnet() {
        use crate::Schedule;
        let config = DiscoveryConfig {
            name: "test".into(),
            enabled: true,
            schedule: Schedule::Calendar {
                months: vec![],
                days_of_month: vec![],
                time: chrono::NaiveTime::from_hms_opt(3, 0, 0).unwrap(),
            },
            subnets: vec![SubnetSpec {
                ip: "10.0.0.0".into(),
                mask: "255.255.255.0".into(),
                port: 161,
                credentials: vec![],
                oids: Default::default(),
                labels: Default::default(),
                snmp_timeout_ms: None,
                snmp_retries: None,
                create_dead_devices: true,
            }],
        };
        assert!(find_subnet_spec_for_ip(&[config], "192.168.1.5").is_none());
    }
}
