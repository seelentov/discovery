//! SNMP Trap/Inform reception — wraps `async_snmp::notification` (v1 Trap-PDU, v2c/v3
//! Trap-PDU, confirmed Inform with the ack handshake handled entirely inside the
//! dependency) so nothing above this crate ever touches `async-snmp` types directly, same
//! boundary discipline [`crate::client::RealSnmpClient`] already keeps for outbound polls.
//!
//! **What this module deliberately does NOT do**, by design (see
//! `docs/Changelog/2026-08-30 - SNMP Trap.md`): validate a trap's source IP against a
//! known device, or check whether its community/USM identity actually matches *that*
//! device's configured credentials. Both need `DeviceStore`, which this crate can't and
//! shouldn't depend on — `discovery-agent`'s trap listener does that after `recv()`
//! returns, using [`DecodedTrap::auth`]. The one piece of auth this module *does* own is
//! the SNMPv3 USM cryptographic check itself (HMAC verification, decryption) — that's
//! inherent to decoding a v3 packet at all, `async-snmp` does it internally against
//! whichever [`TrapUsmUser`]s were registered when the receiver was built.
use crate::client::{map_auth_protocol, map_priv_protocol, value_to_snmp_value};
use crate::table::snmp_value_to_metric;
use discovery_core::{MetricValue, SnmpV3Credentials};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use tracing::warn;

pub use async_snmp::{generate_engine_id, AuthoritativeEngine, PersistedAuthoritativeEngine};

/// Mirrors `async_snmp::SecurityLevel` — re-exposed as this crate's own type so callers
/// never need the `async-snmp` dependency directly, same reasoning as [`DecodedTrap`]
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrapSecurityLevel {
    NoAuthNoPriv,
    AuthNoPriv,
    AuthPriv,
}

fn map_security_level(level: async_snmp::SecurityLevel) -> TrapSecurityLevel {
    match level {
        async_snmp::SecurityLevel::NoAuthNoPriv => TrapSecurityLevel::NoAuthNoPriv,
        async_snmp::SecurityLevel::AuthNoPriv => TrapSecurityLevel::AuthNoPriv,
        async_snmp::SecurityLevel::AuthPriv => TrapSecurityLevel::AuthPriv,
    }
}

/// What identity a trap/inform claims, unverified against any particular device — see this
/// module's docs for why that check lives one layer up.
#[derive(Debug, Clone)]
pub enum TrapAuth {
    /// v1/v2c — cleartext on the wire, `async-snmp` does no verification of it at all
    /// (this crate never configures a community allowlist on the receiver, deliberately —
    /// see `build_trap_receiver`'s docs).
    Community(String),
    /// v3 — `security_level` reflects what the USM check inside `async-snmp` actually
    /// established for this packet (only possible because `username` matched one of the
    /// `TrapUsmUser`s the receiver was built with; an unrecognized v3 username never
    /// reaches here at all, `async-snmp` drops it before `recv()` returns). The caller
    /// still must separately confirm `username` matches the resolved device's *own*
    /// configured user — a receiver can know several users at once.
    UsmV3 {
        username: String,
        security_level: TrapSecurityLevel,
    },
}

/// One decoded trap/inform, protocol layer only — no device/profile concepts, no
/// knowledge of `discovery-dsl::TrapSpec`. `varbinds` is *every* varbind the packet
/// carried, keyed by dotted OID string, already converted to [`MetricValue`] — the caller
/// picks out whatever a profile's `TrapEventSpec::varbinds` declares by OID; a varbind
/// nobody's profile cares about is simply never looked up, not filtered here (filtering
/// per-profile would mean this crate would need to know about profiles, which it
/// shouldn't).
#[derive(Debug, Clone)]
pub struct DecodedTrap {
    pub source: SocketAddr,
    pub trap_oid: String,
    /// sysUpTime.0 in centiseconds, straight off the wire — not currently used for
    /// sequencing (see the design changelog for why `ttl_secs`-based staleness was chosen
    /// over strict reordering defenses), kept for future use and for raw-history display.
    pub uptime_centis: u32,
    pub varbinds: BTreeMap<String, MetricValue>,
    pub auth: TrapAuth,
}

fn decode(received: async_snmp::ReceivedNotification) -> anyhow::Result<DecodedTrap> {
    use async_snmp::Notification;

    let trap_oid = received
        .notification
        .trap_oid()
        .map_err(|e| anyhow::anyhow!("invalid trap OID: {e}"))?
        .to_string();
    let uptime_centis = received.notification.uptime();

    let mut varbinds = BTreeMap::new();
    for vb in received.notification.varbinds() {
        match value_to_snmp_value(vb.value.clone()) {
            Ok(snmp_value) => {
                varbinds.insert(vb.oid.to_string(), snmp_value_to_metric(&snmp_value));
            }
            // A single unusual varbind (an exception value inside a trap, which real
            // devices essentially never send) must not take down decode of the whole
            // packet — same "degrade one field, not the whole thing" philosophy as the
            // rest of this pipeline.
            Err(e) => {
                warn!(oid = %vb.oid, error = %e, "trap varbind failed to convert — skipping this field, keeping the rest of the packet")
            }
        }
    }

    let auth = match &received.notification {
        Notification::TrapV1 { community, .. }
        | Notification::TrapV2c { community, .. }
        | Notification::InformV2c { community, .. } => {
            TrapAuth::Community(String::from_utf8_lossy(community.as_bytes()).to_string())
        }
        Notification::TrapV3 {
            username,
            security_level,
            ..
        }
        | Notification::InformV3 {
            username,
            security_level,
            ..
        } => TrapAuth::UsmV3 {
            username: String::from_utf8_lossy(username).to_string(),
            security_level: map_security_level(*security_level),
        },
    };

    Ok(DecodedTrap {
        source: received.source,
        trap_oid,
        uptime_centis,
        varbinds,
        auth,
    })
}

/// A long-lived UDP trap/inform receiver — one per `discovery-agent` process while
/// `[snmp_trap].enabled = true`. Rebuilt (not mutated) via [`build_trap_receiver`]
/// whenever the set of known SNMPv3 users changes, since `async-snmp`'s
/// `NotificationReceiver` has no way to add/remove USM users after construction.
pub struct TrapListener {
    receiver: async_snmp::notification::NotificationReceiver,
}

impl TrapListener {
    /// Blocks until the next accepted trap/inform. Malformed/rejected datagrams (bad BER,
    /// unrecognized v3 user, community/USM check failures `async-snmp` itself already
    /// enforces) are skipped internally by the receiver and never surface here at all —
    /// only [`decode`]'s own narrower failures (an unparseable `trap_oid`) become `Err`.
    pub async fn recv(&self) -> anyhow::Result<DecodedTrap> {
        let received = self
            .receiver
            .recv()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        decode(received)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.receiver.local_addr()
    }
}

/// One SNMPv3 user a trap receiver should recognize — `username` plus the same
/// `SnmpV3Credentials` shape already used for outbound polling. **Caveat inherited from
/// `async-snmp`'s model (accepted 2026-08-30, direct user decision): keyed by `username`
/// alone, not per-device** — two devices sharing one username must share one password,
/// same auth/priv settings, or only one of them will actually authenticate.
pub struct TrapUsmUser {
    pub username: String,
    pub credentials: SnmpV3Credentials,
}

/// Builds (or rebuilds) a trap receiver bound to `bind_addr`. `v3_users` empty just skips
/// SNMPv3 setup entirely — the receiver still accepts v1/v2c (community is read but never
/// filtered by this crate; see [`TrapAuth::Community`]'s docs for why that check lives in
/// `discovery-agent` instead). Community filtering is deliberately never configured here
/// either, same reasoning.
///
/// `engine` is required whenever `v3_users` is non-empty — `discovery-agent` owns loading/
/// persisting it (via `SettingsStore`), since `AuthoritativeEngine::install`/`restart`'s
/// persistence callback needs a store this crate doesn't and shouldn't depend on.
pub async fn build_trap_receiver(
    bind_addr: &str,
    engine: Option<AuthoritativeEngine>,
    v3_users: &[TrapUsmUser],
) -> anyhow::Result<TrapListener> {
    use async_snmp::notification::NotificationReceiver;

    if v3_users.is_empty() {
        let receiver = NotificationReceiver::bind(bind_addr)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        return Ok(TrapListener { receiver });
    }

    let engine = engine.ok_or_else(|| {
        anyhow::anyhow!("SNMPv3 trap users configured but no AuthoritativeEngine was supplied")
    })?;
    let mut builder = NotificationReceiver::builder()
        .bind(bind_addr)
        .authoritative_engine(engine);
    for user in v3_users {
        let creds = &user.credentials;
        if creds.auth.is_none() && creds.priv_.is_some() {
            anyhow::bail!("SNMPv3 trap user {:?}: privacy without authentication (privNoAuth) is not a valid security level", user.username);
        }
        builder = builder
            .usm_user(user.username.clone(), |u| {
                match (&creds.auth, &creds.priv_) {
                    (None, None) => Ok(u),
                    (Some(auth), None) => {
                        u.auth(map_auth_protocol(auth.protocol), auth.passphrase.as_bytes())
                    }
                    (Some(auth), Some(priv_)) => u.auth_priv(
                        map_auth_protocol(auth.protocol),
                        auth.passphrase.as_bytes(),
                        map_priv_protocol(priv_.protocol),
                        priv_.passphrase.as_bytes(),
                    ),
                    (None, Some(_)) => unreachable!("checked above"),
                }
            })
            .map_err(|e| {
                anyhow::anyhow!(
                    "invalid SNMPv3 trap credentials for user {:?}: {e}",
                    user.username
                )
            })?;
    }
    let receiver = builder
        // Acceptance here is "did protocol processing succeed", not "do we trust this" —
        // the real trust decision (does this device's stored creds match) happens in
        // discovery-agent after recv(), which needs the resolved Device to check against.
        .accept_all_notifications()
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(TrapListener { receiver })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::{oid, Auth, AuthProtocol, Client, PrivProtocol, UsmConfig, Value, VarBind};
    use discovery_core::device::SnmpAuthProtocol as CoreAuthProtocol;
    use discovery_core::device::SnmpPrivProtocol as CorePrivProtocol;
    use discovery_core::{SnmpV3AuthCreds, SnmpV3Credentials, SnmpV3PrivCreds};

    /// End-to-end against real wire encode/decode (not a mock) — a `Client` sends an
    /// actual UDP v2c trap, `TrapListener` receives and decodes it. `bind("127.0.0.1:0")`
    /// picks a free port so tests never collide.
    #[tokio::test]
    async fn sends_and_decodes_a_v2c_trap_with_varbinds() {
        let listener = build_trap_receiver("127.0.0.1:0", None, &[]).await.unwrap();
        let addr = listener.local_addr();

        let client = Client::builder(addr.to_string(), Auth::v2c("public"))
            .connect()
            .await
            .unwrap();
        let link_down = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3);
        let if_index_oid = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1);
        client
            .send_trap(
                &link_down,
                12345,
                vec![VarBind::new(if_index_oid.clone(), Value::Integer(3))],
            )
            .await
            .unwrap();

        let decoded = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("must receive within timeout")
            .unwrap();

        assert_eq!(decoded.trap_oid, "1.3.6.1.6.3.1.1.5.3");
        assert_eq!(decoded.uptime_centis, 12345);
        assert_eq!(
            decoded.varbinds.get("1.3.6.1.2.1.2.2.1.1"),
            Some(&MetricValue::Int(3))
        );
        match decoded.auth {
            TrapAuth::Community(c) => assert_eq!(c, "public"),
            TrapAuth::UsmV3 { .. } => panic!("v2c trap must decode as Community auth"),
        }
    }

    /// v3 authPriv — proves the USM cryptographic round trip actually works through this
    /// crate's wrapper, not just that the types compile.
    #[tokio::test]
    async fn sends_and_decodes_a_v3_trap_with_auth_priv() {
        let engine = AuthoritativeEngine::install(b"trap-test-engine".to_vec(), |_| {
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
        let creds = SnmpV3Credentials {
            user: "trapuser".to_string(),
            auth: Some(SnmpV3AuthCreds {
                protocol: CoreAuthProtocol::Sha256,
                passphrase: "authpass12345678".to_string(),
            }),
            priv_: Some(SnmpV3PrivCreds {
                protocol: CorePrivProtocol::Aes128,
                passphrase: "privpass12345678".to_string(),
            }),
        };
        let listener = build_trap_receiver(
            "127.0.0.1:0",
            Some(engine.clone()),
            &[TrapUsmUser {
                username: "trapuser".to_string(),
                credentials: creds,
            }],
        )
        .await
        .unwrap();
        let addr = listener.local_addr();

        let usm = UsmConfig::new("trapuser")
            .auth_priv(
                AuthProtocol::Sha256,
                "authpass12345678",
                PrivProtocol::Aes128,
                "privpass12345678",
            )
            .unwrap();
        let client = Client::builder(addr.to_string(), usm)
            .local_authoritative_engine(engine)
            .connect()
            .await
            .unwrap();
        let link_up = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4);
        client.send_trap(&link_up, 999, vec![]).await.unwrap();

        let decoded = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("must receive within timeout")
            .unwrap();
        assert_eq!(decoded.trap_oid, "1.3.6.1.6.3.1.1.5.4");
        match decoded.auth {
            TrapAuth::UsmV3 {
                username,
                security_level,
            } => {
                assert_eq!(username, "trapuser");
                assert_eq!(security_level, TrapSecurityLevel::AuthPriv);
            }
            TrapAuth::Community(_) => panic!("v3 trap must decode as UsmV3 auth"),
        }
    }

    /// The username-keyed-not-per-device caveat (2026-08-30, direct user decision) is only
    /// safe if a genuinely *unregistered* v3 user is actually dropped, not silently
    /// delivered with some default/unauthenticated identity — this is what makes it okay
    /// that `discovery-agent` trusts `TrapAuth::UsmV3::username` afterward.
    #[tokio::test]
    async fn an_unregistered_v3_user_never_arrives() {
        let engine = AuthoritativeEngine::install(b"trap-test-engine-2".to_vec(), |_| {
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
        let known = SnmpV3Credentials {
            user: "knownuser".to_string(),
            auth: Some(SnmpV3AuthCreds {
                protocol: CoreAuthProtocol::Sha256,
                passphrase: "authpass12345678".to_string(),
            }),
            priv_: None,
        };
        let listener = build_trap_receiver(
            "127.0.0.1:0",
            Some(engine.clone()),
            &[TrapUsmUser {
                username: "knownuser".to_string(),
                credentials: known,
            }],
        )
        .await
        .unwrap();
        let addr = listener.local_addr();

        let usm = UsmConfig::new("strangeruser")
            .auth(AuthProtocol::Sha256, "somepassword123")
            .unwrap();
        let client = Client::builder(addr.to_string(), usm)
            .local_authoritative_engine(engine)
            .connect()
            .await
            .unwrap();
        let cold_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
        // The send itself may or may not error (engine discovery can still succeed) — what
        // matters is whether the receiver ever hands it to the application.
        let _ = client.send_trap(&cold_start, 1, vec![]).await;

        let outcome =
            tokio::time::timeout(std::time::Duration::from_millis(500), listener.recv()).await;
        assert!(outcome.is_err(), "an unrecognized v3 username must never be delivered, not even as an unauthenticated notification");
    }

    #[tokio::test]
    async fn no_v3_users_still_accepts_v2c() {
        let listener = build_trap_receiver("127.0.0.1:0", None, &[]).await.unwrap();
        assert!(listener.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn priv_without_auth_is_rejected_up_front() {
        let engine = AuthoritativeEngine::install(b"trap-test-engine-3".to_vec(), |_| {
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
        let broken = SnmpV3Credentials {
            user: "broken".to_string(),
            auth: None,
            priv_: Some(SnmpV3PrivCreds {
                protocol: CorePrivProtocol::Aes128,
                passphrase: "privpass12345678".to_string(),
            }),
        };
        let result = build_trap_receiver(
            "127.0.0.1:0",
            Some(engine),
            &[TrapUsmUser {
                username: "broken".to_string(),
                credentials: broken,
            }],
        )
        .await;
        match result {
            Ok(_) => panic!("privNoAuth must be rejected before a receiver is built"),
            Err(e) => assert!(e.to_string().contains("privNoAuth")),
        }
    }
}
