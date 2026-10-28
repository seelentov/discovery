use async_trait::async_trait;
use discovery_core::{DeviceTarget, SnmpAuth, SnmpAuthProtocol, SnmpPrivProtocol, SnmpVersion};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

#[derive(Debug, Clone)]
pub enum SnmpValue {
    Integer(i64),
    OctetString(String),
    ObjectId(String),
    Counter(u64),
    Gauge(u64),
    TimeTicks(u64),
    Null,
}

impl SnmpValue {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            SnmpValue::Integer(v) => Some(*v),
            SnmpValue::Counter(v) | SnmpValue::Gauge(v) | SnmpValue::TimeTicks(v) => {
                Some(*v as i64)
            }
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            SnmpValue::OctetString(v) | SnmpValue::ObjectId(v) => Some(v),
            _ => None,
        }
    }
}

/// Abstraction over "how do we talk SNMP to a device". Kept trait-based so the whole
/// pipeline (discovery, polling, profile matching) can run against [`crate::FakeSnmpClient`]
/// in tests and in the demo binary without any real network I/O or external SNMP agent.
#[async_trait]
pub trait SnmpClient: Send + Sync {
    async fn get(&self, target: &DeviceTarget, oid: &str) -> anyhow::Result<SnmpValue>;
    async fn walk(
        &self,
        target: &DeviceTarget,
        oid: &str,
    ) -> anyhow::Result<Vec<(String, SnmpValue)>>;

    /// Fetches several OIDs from the same device in as few round trips as the
    /// implementation can manage (added 2026-08-18, direct user request — batching
    /// instead of one sequential `get()` per metric, see `discovery/CLAUDE.md`'s "SNMP
    /// GetBulk/multi-OID batching" section for the full reasoning).
    ///
    /// Returns exactly one result per input OID, **in the same order** — never a single
    /// all-or-nothing outcome for the whole batch. This is load-bearing, not a style
    /// choice: a device that supports 5 of a profile's 6 metrics must still report the 5
    /// good ones, the same way 6 independent `get()` calls always have — one unsupported
    /// OID must not blank out the rest. `RealSnmpClient`'s override is what actually
    /// batches (via `async-snmp`'s `get_many`, one packet for all OIDs at once); this
    /// default implementation is the trivial, always-correct fallback — sequential
    /// `get()` calls — used by `FakeSnmpClient` (no real wire cost to save) and by
    /// anything else that doesn't override it.
    async fn get_multi(
        &self,
        target: &DeviceTarget,
        oids: &[String],
    ) -> Vec<anyhow::Result<SnmpValue>> {
        let mut results = Vec::with_capacity(oids.len());
        for oid in oids {
            results.push(self.get(target, oid).await);
        }
        results
    }
}

/// Real SNMP client backed by the `async-snmp` crate (SNMPv1/v2c/v3 USM auth/priv).
/// Replaced the `csnmp`-backed client 2026-08-29 (direct user request — SNMPv3 support;
/// `csnmp` only ever implemented v1/v2c, see `discovery/CLAUDE.md`'s SNMPv3 changelog
/// entry). Verified live against a real `snmpd` (both v2c and v3 authPriv) before this
/// rewrite — see that changelog entry for the recorded spike output.
///
/// `engine_cache` is shared across every v3 connection this client makes (constructed once
/// in [`Self::new`], not per-call) — SNMPv3's engine-ID discovery handshake is an extra
/// round trip before the request that actually matters even goes out; without caching,
/// every single `get`/`walk`/`get_multi` call on a v3 target would redo it, doubling
/// latency on a path (`MetricPoll`) that runs on every device's recurring poll cycle. v1/v2c
/// has no engine handshake at all, so the cache is simply unused for those targets.
pub struct RealSnmpClient {
    engine_cache: Arc<async_snmp::EngineCache>,
}

impl RealSnmpClient {
    pub fn new() -> Self {
        Self {
            engine_cache: Arc::new(async_snmp::EngineCache::new()),
        }
    }
}

impl Default for RealSnmpClient {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn map_auth_protocol(protocol: SnmpAuthProtocol) -> async_snmp::AuthProtocol {
    use async_snmp::AuthProtocol as A;
    match protocol {
        SnmpAuthProtocol::Md5 => A::Md5,
        SnmpAuthProtocol::Sha1 => A::Sha1,
        SnmpAuthProtocol::Sha224 => A::Sha224,
        SnmpAuthProtocol::Sha256 => A::Sha256,
        SnmpAuthProtocol::Sha384 => A::Sha384,
        SnmpAuthProtocol::Sha512 => A::Sha512,
    }
}

pub(crate) fn map_priv_protocol(protocol: SnmpPrivProtocol) -> async_snmp::PrivProtocol {
    use async_snmp::PrivProtocol as P;
    match protocol {
        SnmpPrivProtocol::Des => P::Des,
        SnmpPrivProtocol::Des3 => P::Des3,
        SnmpPrivProtocol::Aes128 => P::Aes128,
        SnmpPrivProtocol::Aes192Blumenthal => P::Aes192Blumenthal,
        SnmpPrivProtocol::Aes192Reeder => P::Aes192Reeder,
        SnmpPrivProtocol::Aes256Blumenthal => P::Aes256Blumenthal,
        SnmpPrivProtocol::Aes256Reeder => P::Aes256Reeder,
    }
}

/// Builds the `async-snmp` auth config for one [`SnmpAuth`]. `UsmV3`'s `priv_` set without
/// `auth` (privNoAuth) isn't a real SNMPv3 security level — same invariant the REST/API
/// boundary is expected to reject (see `discovery_core::SnmpV3Credentials`'s docs);
/// checked again here since this is the last point before it would otherwise silently
/// degrade to noAuthNoPriv.
fn build_auth(auth: &SnmpAuth) -> anyhow::Result<async_snmp::Auth> {
    match auth {
        SnmpAuth::Community { version, community } => Ok(match version {
            SnmpVersion::V1 => async_snmp::Auth::v1(community.clone()),
            SnmpVersion::V2c => async_snmp::Auth::v2c(community.clone()),
        }),
        SnmpAuth::UsmV3(creds) => {
            let usm = async_snmp::UsmConfig::new(creds.user.clone());
            let usm = match (&creds.auth, &creds.priv_) {
                (None, None) => usm,
                (Some(auth), None) => usm.auth(map_auth_protocol(auth.protocol), auth.passphrase.as_bytes())?,
                (Some(auth), Some(priv_)) => {
                    usm.auth_priv(map_auth_protocol(auth.protocol), auth.passphrase.as_bytes(), map_priv_protocol(priv_.protocol), priv_.passphrase.as_bytes())?
                }
                (None, Some(_)) => anyhow::bail!("SNMPv3 privacy without authentication (privNoAuth) is not a valid security level"),
            };
            Ok(usm.into())
        }
    }
}

impl RealSnmpClient {
    async fn connect(
        &self,
        target: &DeviceTarget,
    ) -> anyhow::Result<async_snmp::Client<async_snmp::UdpHandle>> {
        let auth = build_auth(&target.auth)?;
        let retry = async_snmp::Retry::fixed(target.retries, Duration::ZERO)
            .map_err(|e| anyhow::anyhow!("invalid retry config: {e}"))?;
        let is_v3 = matches!(target.auth, SnmpAuth::UsmV3(_));
        let mut builder = async_snmp::Client::builder((target.ip.as_str(), target.port), auth)
            .request_timeout(Duration::from_millis(target.timeout_ms))
            .retry(retry);
        if is_v3 {
            builder = builder.engine_cache(self.engine_cache.clone());
        }
        builder.connect().await.map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// `OCTET STRING`/`Opaque`/`NSAP` are frequently genuine binary data, not text — most
/// visibly `lldpRemChassisId`/`lldpLocChassisId` when the vendor's `...ChassisIdSubtype` is
/// `macAddress` (raw 6-byte MAC, not a string at all). Found live against real vendor
/// hardware (Магистraль, 2026-09-13/14, `docs/Roadmap.md`): `String::from_utf8_lossy` on
/// those bytes produced values full of U+FFFD replacement characters — LLDP topology
/// reconciliation couldn't match a chassis id against itself if it was garbled two
/// different ways on each end's decode, and the whole thing was silently unusable, not just
/// ugly. Falls back to a colon-separated hex string (`"aa:bb:cc:dd:ee:ff"`, the conventional
/// MAC rendering) whenever the bytes aren't valid UTF-8 — this is a heuristic (no per-value
/// `...Subtype` is consulted; a small blob of unrelated binary data that happens to decode
/// as valid UTF-8 slips through unrecognized), not full LLDP-MIB-subtype-aware decoding, but
/// it turns silent, lossy corruption into a stable, comparable, human-legible value for
/// every genuinely-binary OCTET STRING, and never touches values that are real text
/// (`sysDescr`, community strings, etc. — always valid UTF-8 in practice).
fn decode_octet_string(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

/// Converts one decoded SNMP value. The three SNMPv3/v2c exception values (`NoSuchObject`/
/// `NoSuchInstance`/`EndOfMibView`) are ordinary *values* on the wire (not response-shape
/// anomalies, not transport errors) — `async-snmp` surfaces them as `Value` variants rather
/// than failing the request, so converting them to `Err` here is what makes "this OID
/// doesn't exist on this device" behave like a normal per-OID failure to the rest of this
/// codebase, the same way it did under the old `csnmp`-backed client.
pub(crate) fn value_to_snmp_value(value: async_snmp::Value) -> anyhow::Result<SnmpValue> {
    use async_snmp::Value as V;
    match value {
        V::Integer(v) => Ok(SnmpValue::Integer(v as i64)),
        V::OctetString(v) | V::Opaque(v) | V::Nsap(v) => {
            Ok(SnmpValue::OctetString(decode_octet_string(&v)))
        }
        V::ObjectIdentifier(v) => Ok(SnmpValue::ObjectId(v.to_string())),
        V::IpAddress(v) => Ok(SnmpValue::OctetString(
            v.iter().map(u8::to_string).collect::<Vec<_>>().join("."),
        )),
        V::Counter32(v) => Ok(SnmpValue::Counter(v as u64)),
        V::Counter64(v) => Ok(SnmpValue::Counter(v)),
        V::Gauge32(v) | V::UInteger32(v) => Ok(SnmpValue::Gauge(v as u64)),
        V::TimeTicks(v) => Ok(SnmpValue::TimeTicks(v as u64)),
        V::Null => Ok(SnmpValue::Null),
        V::NoSuchObject => {
            anyhow::bail!("noSuchObject: this OID is not present in the device's MIB view")
        }
        V::NoSuchInstance => {
            anyhow::bail!("noSuchInstance: the object exists but this instance does not")
        }
        V::EndOfMibView => {
            anyhow::bail!("endOfMibView: reached the end of the MIB (unexpected for a GET)")
        }
        // `Value` is `#[non_exhaustive]` (forward compatibility for new wire types the
        // crate might add later) — covers both `Value::Unknown` and any future variant
        // the same way the old `csnmp`-backed client's catchall did.
        _ => Ok(SnmpValue::Null),
    }
}

#[async_trait]
impl SnmpClient for RealSnmpClient {
    async fn get(&self, target: &DeviceTarget, oid: &str) -> anyhow::Result<SnmpValue> {
        let client = self.connect(target).await?;
        let object_id: async_snmp::Oid = oid
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid OID {oid}: {e}"))?;
        let response = client
            .get(&object_id)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let varbind = response.single().ok_or_else(|| {
            anyhow::anyhow!("unexpected response shape: {:?}", response.anomalies)
        })?;
        value_to_snmp_value(varbind.value.clone())
    }

    async fn walk(
        &self,
        target: &DeviceTarget,
        oid: &str,
    ) -> anyhow::Result<Vec<(String, SnmpValue)>> {
        let client = self.connect(target).await?;
        let object_id: async_snmp::Oid = oid
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid OID {oid}: {e}"))?;
        let varbinds = client
            .walk(object_id)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        varbinds
            .into_iter()
            .map(|vb| Ok((vb.oid.to_string(), value_to_snmp_value(vb.value)?)))
            .collect()
    }

    /// Batches via `async-snmp`'s `Client::get_many` — one request carrying every OID as
    /// its own binding, instead of N. **Not** GETBULK (that's what `walk`'s bulk-walk path
    /// uses internally, for iterating a subtree — a different shape of request than a
    /// fixed set of named scalar OIDs).
    ///
    /// A per-OID miss (an unsupported OID mixed in with supported ones) is *not* an
    /// all-or-nothing failure here: `async-snmp` reports it as a shape anomaly on an
    /// otherwise-successful response (SNMPv2c/v3 return `noSuchObject`/`noSuchInstance` as
    /// an ordinary per-binding value, not a whole-PDU error) — falling back to sequential
    /// per-OID `get()` in that case reproduces the old `csnmp`-era behavior (5 of 6 metrics
    /// still succeed) without needing `async-snmp`'s crate-specific anomaly type as this
    /// trait's public contract. A genuine `Err` (network/timeout/protocol failure) applies
    /// uniformly to every OID regardless of strategy, so it's returned directly — no
    /// wasted sequential retries against a target that's already confirmed unreachable.
    async fn get_multi(
        &self,
        target: &DeviceTarget,
        oids: &[String],
    ) -> Vec<anyhow::Result<SnmpValue>> {
        if oids.is_empty() {
            return Vec::new();
        }
        if oids.len() == 1 {
            return vec![self.get(target, &oids[0]).await];
        }

        let client = match self.connect(target).await {
            Ok(c) => c,
            Err(e) => {
                return oids
                    .iter()
                    .map(|_| Err(anyhow::anyhow!(e.to_string())))
                    .collect()
            }
        };

        let parsed: Result<Vec<async_snmp::Oid>, _> =
            oids.iter().map(|o| o.parse::<async_snmp::Oid>()).collect();
        let object_ids = match parsed {
            Ok(v) => v,
            Err(e) => {
                return oids
                    .iter()
                    .map(|_| Err(anyhow::anyhow!("invalid OID: {e}")))
                    .collect()
            }
        };

        match client.get_many(&object_ids).await {
            Ok(response) if response.anomalies.is_empty() => response
                .varbinds
                .into_iter()
                .map(|vb| value_to_snmp_value(vb.value))
                .collect(),
            Ok(response) => {
                warn!(ip = %target.ip, oid_count = oids.len(), anomalies = ?response.anomalies, "SNMP batched get returned a shape anomaly — falling back to per-OID gets for this poll");
                let mut results = Vec::with_capacity(oids.len());
                for oid in oids {
                    results.push(self.get(target, oid).await);
                }
                results
            }
            Err(e) => {
                warn!(ip = %target.ip, oid_count = oids.len(), error = %e, "SNMP batched get failed");
                oids.iter()
                    .map(|_| Err(anyhow::anyhow!(e.to_string())))
                    .collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery_core::SnmpVersion;

    fn dead_target() -> DeviceTarget {
        DeviceTarget {
            ip: "127.0.0.1".into(),
            port: 39999, // an obscure high port essentially guaranteed unbound in test environments
            auth: SnmpAuth::Community {
                version: SnmpVersion::V2c,
                community: "public".into(),
            },
            timeout_ms: 200,
            retries: 1, // 2 attempts total — worst case ~400ms, far under the 5s outer bound below
        }
    }

    #[test]
    fn decode_octet_string_passes_real_text_through_unchanged() {
        assert_eq!(
            decode_octet_string(b"Cisco IOS Software"),
            "Cisco IOS Software"
        );
        assert_eq!(decode_octet_string(b"public"), "public");
    }

    /// The real bug, made concrete (Магистраль, 2026-09-13/14, `docs/Roadmap.md`): a
    /// `macAddress`-subtype `lldpRemChassisId` is 6 raw binary bytes, not text — decoding
    /// it as lossy UTF-8 produced a string full of U+FFFD replacement characters, silently
    /// corrupting the one field LLDP topology reconciliation matches devices on.
    #[test]
    fn decode_octet_string_renders_non_utf8_bytes_as_hex_not_replacement_characters() {
        let mac_bytes = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let decoded = decode_octet_string(&mac_bytes);
        assert_eq!(decoded, "aa:bb:cc:dd:ee:ff");
        assert!(
            !decoded.contains('\u{fffd}'),
            "must never contain the lossy-UTF-8 replacement character: {decoded}"
        );
    }

    /// The real bug, made concrete: before the fix (found live 2026-08-16, against the old
    /// `csnmp`-backed client), this whole test would hang forever. The outer
    /// `tokio::time::timeout` is the proof — it fails the test loudly if `get` doesn't
    /// return well within it, rather than the test process just hanging silently.
    #[tokio::test]
    async fn get_against_an_unresponsive_target_fails_within_the_configured_timeout_not_forever() {
        let client = RealSnmpClient::new();
        let target = dead_target();

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            client.get(&target, "1.3.6.1.2.1.1.1.0"),
        )
        .await;
        let result = outcome.expect(
            "get() must return within the configured timeout, not hang past the outer bound",
        );
        assert!(
            result.is_err(),
            "nothing is listening on that port — the SNMP get must fail, not succeed"
        );
    }

    #[tokio::test]
    async fn get_multi_with_zero_oids_returns_immediately_without_a_network_round_trip() {
        let client = RealSnmpClient::new();
        let results = client.get_multi(&dead_target(), &[]).await;
        assert!(results.is_empty());
    }

    /// Same "must not hang forever" guarantee as the single-`get` test above, extended to
    /// the batched path — and confirms a *uniform* failure (dead device) produces one
    /// `Err` per requested OID, not a single top-level error the caller would have to
    /// special-case away from the per-metric `Vec` shape.
    #[tokio::test]
    async fn get_multi_against_an_unresponsive_target_fails_every_oid_within_the_timeout() {
        let client = RealSnmpClient::new();
        let target = DeviceTarget {
            retries: 0,
            ..dead_target()
        };
        let oids = vec![
            "1.3.6.1.2.1.1.1.0".to_string(),
            "1.3.6.1.2.1.1.5.0".to_string(),
        ];

        let outcome =
            tokio::time::timeout(Duration::from_secs(5), client.get_multi(&target, &oids)).await;
        let results =
            outcome.expect("get_multi() must return within the configured timeout, not hang");
        assert_eq!(
            results.len(),
            2,
            "one result per requested OID, even on total failure"
        );
        assert!(
            results.iter().all(|r| r.is_err()),
            "nothing is listening — every OID must come back Err"
        );
    }

    #[tokio::test]
    async fn build_auth_rejects_priv_without_auth() {
        let auth = SnmpAuth::UsmV3(discovery_core::SnmpV3Credentials {
            user: "monitor".into(),
            auth: None,
            priv_: Some(discovery_core::SnmpV3PrivCreds {
                protocol: SnmpPrivProtocol::Aes128,
                passphrase: "privpass123".into(),
            }),
        });
        assert!(build_auth(&auth).is_err());
    }

    /// **Live-only, not run by normal `cargo test`** (`cargo test -- --ignored`) — needs a
    /// real `discovery-devicefarm` running with a device at `127.50.2.21:1161`/`hostpass`
    /// that has `sys_descr` but *not* the Cisco `cpu` OID (matches this project's
    /// established "verify live, not just by inspection" discipline — see
    /// `discovery/CLAUDE.md`). Confirms the two things a hand-trace of the code can't: the
    /// batched happy path actually returns real values over the wire, and a genuine
    /// per-OID miss (a shape anomaly, not an all-or-nothing failure) genuinely triggers the
    /// per-OID fallback — `sys_descr` must still come back `Ok` even though `cpu` doesn't
    /// exist on this device.
    #[tokio::test]
    #[ignore]
    async fn live_get_multi_batches_when_everything_is_supported_and_falls_back_on_a_partial_miss()
    {
        let client = RealSnmpClient::new();
        let target = DeviceTarget {
            ip: "127.50.2.21".into(),
            port: 1161,
            auth: SnmpAuth::Community {
                version: SnmpVersion::V2c,
                community: "hostpass".into(),
            },
            timeout_ms: 1000,
            retries: 1,
        };

        // Happy path: every OID this device actually has, batched in one call.
        let supported = vec![
            "1.3.6.1.2.1.1.1.0".to_string(),
            "1.3.6.1.2.1.1.5.0".to_string(),
        ];
        let results = client.get_multi(&target, &supported).await;
        assert!(results[0].is_ok(), "sys_descr: {:?}", results[0]);
        assert!(results[1].is_ok(), "sys_name: {:?}", results[1]);

        // Partial miss: sys_descr (real) + the Cisco cpu OID (this device doesn't have it)
        // — must NOT lose sys_descr just because cpu isn't there.
        let mixed = vec![
            "1.3.6.1.2.1.1.1.0".to_string(),
            "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1".to_string(),
        ];
        let results = client.get_multi(&target, &mixed).await;
        assert!(
            results[0].is_ok(),
            "sys_descr must still succeed via the per-OID fallback: {:?}",
            results[0]
        );
        assert!(
            results[1].is_err(),
            "cpu genuinely doesn't exist on this device, must stay Err: {:?}",
            results[1]
        );
    }

    /// **Live-only** (`cargo test -- --ignored`) — needs a real `discovery-devicefarm`
    /// device configured with a v3 USM user `monitor`/SHA/`authpass123`/AES/`privpass123`
    /// at `127.50.2.22:1161` (see the SNMPv3 changelog entry for the devicefarm setup this
    /// mirrors). Confirms authPriv actually round-trips over the wire against a simulated
    /// device, not just against the standalone `snmpd` spike this client was designed
    /// against.
    ///
    /// **Known environment gap (2026-08-29):** in the environment this was developed in,
    /// `snmpsim-lextudio` 1.1.1's bundled `pysnmpcrypto` 0.0.4 silently fails to respond to
    /// *any* v3 request (authPriv **and** authNoPriv — isolated by hand-running a minimal
    /// single-device `snmpsim-command-responder` directly, bypassing `discovery-devicefarm`
    /// entirely; v2c on the same instance works fine) against `cryptography` 50.0.0. Not a
    /// bug in this project's code — `discovery-devicefarm`'s generated `--v3-*` CLI flags
    /// were confirmed byte-for-byte correct via `snmpsim`'s own startup log (`SecurityName:
    /// monitor, authentication protocol: SHA, encryption protocol: AES128`, exactly as
    /// configured) — it's an upstream `snmpsim-lextudio`/`pysnmpcrypto`/`cryptography`
    /// version-compatibility issue. This client's v3 wire behavior is independently
    /// verified live against a real, independent SNMPv3 engine instead (net-snmp's
    /// `snmpd`, both authPriv GET and a negative "OID doesn't exist" check) — see the
    /// changelog entry. Re-run this test after upgrading/pinning a working `snmpsim`/
    /// `pysnmpcrypto` combination to close this gap for good.
    #[tokio::test]
    #[ignore]
    async fn live_v3_auth_priv_get_succeeds_against_devicefarm() {
        let client = RealSnmpClient::new();
        let target = DeviceTarget {
            ip: "127.50.2.22".into(),
            port: 1161,
            auth: SnmpAuth::UsmV3(discovery_core::SnmpV3Credentials {
                user: "monitor".into(),
                auth: Some(discovery_core::SnmpV3AuthCreds {
                    protocol: SnmpAuthProtocol::Sha1,
                    passphrase: "authpass123".into(),
                }),
                priv_: Some(discovery_core::SnmpV3PrivCreds {
                    protocol: SnmpPrivProtocol::Aes128,
                    passphrase: "privpass123".into(),
                }),
            }),
            timeout_ms: 1000,
            retries: 1,
        };

        let result = client.get(&target, "1.3.6.1.2.1.1.1.0").await;
        assert!(result.is_ok(), "v3 authPriv get: {:?}", result);
    }
}
