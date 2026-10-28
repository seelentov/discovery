//! Bounded, explicit service discovery used by the dashboard/API.

use discovery_core::{default_snmp_retries, DeviceTarget, SnmpAuth};
use discovery_dsl::{ProfileFile, ServiceCheckProtocol};
use discovery_servicecheck::{CheckProtocol, CheckTarget, ServiceChecker};
use discovery_snmp::SnmpClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SYS_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";
const MAX_PROBES: usize = 64;
const MAX_TIMEOUT_MS: u64 = 10_000;
const MAX_DISCOVERY_MS: u64 = 30_000;

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceDiscoveryRequest {
    pub ip: String,
    #[serde(default = "default_protocols")]
    pub protocols: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub snmp_auth: Option<SnmpAuth>,
    #[serde(default)]
    pub snmp_port: Option<u16>,
}

fn default_protocols() -> Vec<String> {
    ["snmp", "ssh", "http", "https", "tcp"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_timeout_ms() -> u64 {
    2_000
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceDiscoveryResult {
    pub protocol: String,
    pub profile: Option<String>,
    pub service: Option<String>,
    pub ok: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceDiscoveryResponse {
    pub ip: String,
    pub device_id: Option<uuid::Uuid>,
    pub profile: Option<String>,
    pub created: bool,
    pub results: Vec<ServiceDiscoveryResult>,
}

#[derive(Debug, Clone)]
pub struct SuccessfulProfile {
    pub name: String,
    pub version: String,
    pub priority: i32,
}

pub fn validate_request(request: &ServiceDiscoveryRequest) -> anyhow::Result<std::net::Ipv4Addr> {
    let ip: std::net::Ipv4Addr = request
        .ip
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("ip must be a valid IPv4 address"))?;
    if request.protocols.is_empty() {
        anyhow::bail!("protocols must not be empty");
    }
    if request.protocols.len() > 5 {
        anyhow::bail!("at most 5 protocols may be requested");
    }
    if request.timeout_ms == 0 {
        anyhow::bail!("timeout_ms must be greater than zero");
    }
    Ok(ip)
}

fn service_protocol(protocol: &str) -> Option<CheckProtocol> {
    match protocol {
        "tcp" => Some(CheckProtocol::Tcp),
        "http" => Some(CheckProtocol::Http),
        "https" => Some(CheckProtocol::Https),
        "ssh" => Some(CheckProtocol::Ssh),
        _ => None,
    }
}

fn matches(protocol: CheckProtocol, declared: ServiceCheckProtocol) -> bool {
    matches!(
        (protocol, declared),
        (CheckProtocol::Tcp, ServiceCheckProtocol::Tcp)
            | (CheckProtocol::Http, ServiceCheckProtocol::Http)
            | (CheckProtocol::Https, ServiceCheckProtocol::Https)
            | (CheckProtocol::Ssh, ServiceCheckProtocol::Ssh)
    )
}

fn default_port(protocol: CheckProtocol) -> u16 {
    match protocol {
        CheckProtocol::Tcp => 80,
        CheckProtocol::Http => 80,
        CheckProtocol::Https => 443,
        CheckProtocol::Ssh => 22,
    }
}

/// Run every requested protocol at most once per profile/service declaration. The hard cap
/// keeps a large profile set from turning one API request into an unbounded network scan.
pub async fn discover(
    request: &ServiceDiscoveryRequest,
    profiles: &[ProfileFile],
    checker: &dyn ServiceChecker,
    snmp: &dyn SnmpClient,
) -> (Vec<ServiceDiscoveryResult>, Option<SuccessfulProfile>) {
    let timeout = Duration::from_millis(request.timeout_ms.min(MAX_TIMEOUT_MS));
    let ip = request.ip.trim();
    let mut results = Vec::new();
    let mut winner: Option<SuccessfulProfile> = None;
    let mut probes = 0;
    let run_started = Instant::now();

    for requested in &request.protocols {
        if run_started.elapsed() >= Duration::from_millis(MAX_DISCOVERY_MS) {
            break;
        }
        if requested == "snmp" {
            let started = Instant::now();
            let target = DeviceTarget {
                ip: ip.to_string(),
                port: request.snmp_port.unwrap_or(161),
                auth: request.snmp_auth.clone().unwrap_or_default(),
                timeout_ms: timeout.as_millis() as u64,
                retries: default_snmp_retries(),
            };
            let outcome = tokio::time::timeout(timeout, snmp.get(&target, SYS_OBJECT_ID)).await;
            let (ok, error) = match outcome {
                Ok(Ok(_)) => (true, None),
                Ok(Err(error)) => (false, Some(error.to_string())),
                Err(_) => (false, Some("timed out".to_string())),
            };
            results.push(ServiceDiscoveryResult {
                protocol: requested.clone(),
                profile: None,
                service: None,
                ok,
                latency_ms: Some(started.elapsed().as_millis() as u64),
                error,
            });
            if ok && winner.is_none() {
                winner = profiles
                    .iter()
                    .filter(|p| p.service_checks.checks.iter().any(|c| c.enabled))
                    .max_by_key(|p| {
                        (
                            p.profile.priority,
                            std::cmp::Reverse(p.profile.name.clone()),
                        )
                    })
                    .map(|p| SuccessfulProfile {
                        name: p.profile.name.clone(),
                        version: p.version.clone(),
                        priority: p.profile.priority,
                    });
            }
            continue;
        }

        let Some(protocol) = service_protocol(requested) else {
            results.push(ServiceDiscoveryResult {
                protocol: requested.clone(),
                profile: None,
                service: None,
                ok: false,
                latency_ms: None,
                error: Some("unsupported protocol; use snmp, ssh, http, https, or tcp".into()),
            });
            continue;
        };

        for profile in profiles {
            for check in profile.service_checks.checks.iter().filter(|c| c.enabled) {
                if probes >= MAX_PROBES
                    || run_started.elapsed() >= Duration::from_millis(MAX_DISCOVERY_MS)
                {
                    break;
                }
                if !matches(protocol, check.protocol) {
                    continue;
                }
                probes += 1;
                let target = CheckTarget {
                    protocol,
                    host: ip.to_string(),
                    port: if check.port == 0 {
                        default_port(protocol)
                    } else {
                        check.port
                    },
                    path: check.path_or_default().to_string(),
                    expected_status: check.expected_status,
                    body_contains: check.body_contains.clone(),
                    timeout: check
                        .timeout_ms
                        .map(|ms| Duration::from_millis(ms.min(MAX_TIMEOUT_MS)))
                        .unwrap_or(timeout),
                };
                let outcome = checker.check(&target).await;
                results.push(ServiceDiscoveryResult {
                    protocol: requested.clone(),
                    profile: Some(profile.profile.name.clone()),
                    service: Some(check.name.clone()),
                    ok: outcome.ok,
                    latency_ms: outcome.latency_ms,
                    error: outcome.error,
                });
                if outcome.ok
                    && winner
                        .as_ref()
                        .map_or(true, |current| profile.profile.priority > current.priority)
                {
                    winner = Some(SuccessfulProfile {
                        name: profile.profile.name.clone(),
                        version: profile.version.clone(),
                        priority: profile.profile.priority,
                    });
                }
            }
        }
    }
    (results, winner)
}

pub fn real_checker() -> anyhow::Result<Arc<dyn ServiceChecker>> {
    Ok(Arc::new(discovery_servicecheck::RealServiceChecker::new()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_servicecheck::{CheckOutcome, FakeServiceChecker};
    use discovery_snmp::FakeSnmpClient;

    fn profile() -> ProfileFile {
        serde_json::from_value(serde_json::json!({
            "profile": {"name": "web", "priority": 10},
            "match": {"expression": "true"},
            "service_checks": {"checks": [{
                "name": "admin", "protocol": "http", "port": 8080
            }]}
        }))
        .unwrap()
    }

    #[test]
    fn request_rejects_empty_protocols_and_non_ipv4() {
        let empty = ServiceDiscoveryRequest {
            ip: "10.0.0.1".into(),
            protocols: vec![],
            timeout_ms: 100,
            snmp_auth: None,
            snmp_port: None,
        };
        assert!(validate_request(&empty).is_err());

        let ipv6 = ServiceDiscoveryRequest {
            ip: "::1".into(),
            protocols: vec!["tcp".into()],
            timeout_ms: 100,
            snmp_auth: None,
            snmp_port: None,
        };
        assert!(validate_request(&ipv6).is_err());
    }

    #[tokio::test]
    async fn successful_probe_selects_profile_and_failed_probe_does_not() {
        let checker = FakeServiceChecker::new();
        checker.seed(
            "10.0.0.1",
            8080,
            CheckOutcome {
                ok: true,
                latency_ms: Some(3),
                error: None,
            },
        );
        let snmp = FakeSnmpClient::new();
        let request = ServiceDiscoveryRequest {
            ip: "10.0.0.1".into(),
            protocols: vec!["http".into()],
            timeout_ms: 100,
            snmp_auth: None,
            snmp_port: None,
        };
        let (results, winner) = discover(&request, &[profile()], &checker, &snmp).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].ok);
        assert_eq!(winner.unwrap().name, "web");

        let failed = ServiceDiscoveryRequest {
            ip: "10.0.0.2".into(),
            ..request
        };
        let (_, winner) = discover(&failed, &[profile()], &checker, &snmp).await;
        assert!(winner.is_none());
    }
}
