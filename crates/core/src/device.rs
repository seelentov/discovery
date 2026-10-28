use serde::{Deserialize, Serialize};

/// The one genuinely universal identity anchor for a device: the IP it was reached at.
///
/// **Changed 2026-08-16 (direct user request):** used to also carry `sys_object_id`/
/// `sys_descr`/`sys_name`, fetched unconditionally via hardcoded OIDs every identity
/// cycle regardless of subnet config. The user pointed out this was an unnecessary,
/// inflexible binding — a given deployment's discovery config might not declare exactly
/// those three fields, or might want different ones entirely. Those three (and anything
/// else identity-relevant) are now just ordinary named entries in a subnet's `oids`
/// (`discovery-config-store::SubnetSpec::oids`) — fetched once, landing in the device's
/// unified `Metrics` bag (see `discovery-devices::DeviceStore::resolve`'s docs) under
/// whatever name the deployment chose, not a fixed schema. Kept as a one-field wrapper
/// struct (not inlined to a bare `String`) purely to avoid touching every call site's
/// parameter style; there is room for a genuinely-universal second fact here later if one
/// ever turns up.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceFacts {
    pub ip: String,
}

/// A dotted-quad IPv4 string, as a numeric key that sorts the same way a human expects
/// ("10.0.0.2" before "10.0.0.10") — a plain string comparison doesn't
/// (lexicographic: `'1' < '2'` regardless of what follows). Added 2026-08-21, scale audit:
/// `devices.ip_sort_key` (`discovery-migration`) is computed once via this function at
/// insert time (`ip` is immutable after a device is first resolved) and indexed, so
/// `DeviceStore::list_devices` can `ORDER BY ip_sort_key` at the SQL level instead of
/// loading every row to sort correctly in Rust.
///
/// Unparseable input (shouldn't happen — `DeviceFacts.ip` is always IPv4 today) sorts
/// after every valid address, same "don't panic, don't misplace it silently" fallback the
/// pre-existing Rust-side `ip_sort_key` helper in `discovery-web` used.
pub fn ipv4_to_sort_key(ip: &str) -> i64 {
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => u32::from(addr) as i64,
        Err(_) => i64::MAX,
    }
}

#[cfg(test)]
mod ipv4_to_sort_key_tests {
    use super::*;

    #[test]
    fn sorts_numerically_not_lexicographically() {
        let mut ips = vec!["10.0.0.10", "10.0.0.2", "10.0.0.1"];
        ips.sort_by_key(|ip| ipv4_to_sort_key(ip));
        assert_eq!(ips, vec!["10.0.0.1", "10.0.0.2", "10.0.0.10"]);
    }

    #[test]
    fn unparseable_input_sorts_last() {
        assert!(ipv4_to_sort_key("not-an-ip") > ipv4_to_sort_key("255.255.255.255"));
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SnmpVersion {
    V1,
    V2c,
    // No V3 variant here — v3 doesn't have a community string at all (USM instead), so it
    // can't be expressed as "SnmpVersion + a community" the way v1/v2c can. It lives as its
    // own `SnmpAuth::UsmV3` variant below instead of a third `SnmpVersion` value.
}

/// SNMPv3 USM authentication protocol (RFC 3414/7860). No `None`/no-auth variant here —
/// that's expressed by `SnmpV3Credentials.auth` being `None`, not by a variant of this enum.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SnmpAuthProtocol {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// SNMPv3 USM privacy (encryption) protocol (RFC 3414/3826/draft-reeder-snmpv3-usm-3desede).
///
/// AES-192/256 have two variants each (`Blumenthal`/`Reeder`) because there's no single
/// standard for extending a too-short localized key up to 192/256 bits — RFC 3826 only
/// defines AES-128. Cisco gear conventionally uses the `Reeder` (a.k.a. "Cisco") extension;
/// most other vendors (and net-snmp) use `Blumenthal`. Picking the wrong one doesn't error —
/// it silently produces a key the device can't decrypt with, so this has to be an explicit
/// operator choice, not a default this type guesses at.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SnmpPrivProtocol {
    Des,
    Des3,
    Aes128,
    Aes192Blumenthal,
    Aes192Reeder,
    Aes256Blumenthal,
    Aes256Reeder,
}

/// `passphrase` is plaintext here — always, in memory. Encryption at rest is a store-boundary
/// concern (`discovery-config-store`/`discovery-devices`'s sea-orm implementations encrypt
/// this field with `discovery_core::secret` before writing JSON, decrypt after reading it
/// back), not something this type itself does. RFC 3414 requires passphrases of at least 8
/// octets — validated at the REST/API boundary, not here (same "runtime guard at the edge,
/// not the type system" style as the rest of this codebase, e.g. `discovery_dsl`'s missing-
/// field safety guards).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnmpV3AuthCreds {
    pub protocol: SnmpAuthProtocol,
    pub passphrase: String,
}

/// See [`SnmpV3AuthCreds`]'s docs — same plaintext-in-memory/encrypted-at-rest split.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnmpV3PrivCreds {
    pub protocol: SnmpPrivProtocol,
    pub passphrase: String,
}

/// One SNMPv3 USM identity. `auth`/`priv` encode the three SNMPv3 security levels as nested
/// `Option`s rather than a separate enum: `auth: None` is noAuthNoPriv, `auth: Some(_),
/// priv: None` is authNoPriv, both `Some` is authPriv. `priv: Some(_)` with `auth: None`
/// (privNoAuth) isn't a real SNMPv3 security level — rejected at the REST/API boundary, not
/// encoded as unrepresentable here (would need a 3-variant enum to prevent it at the type
/// level; not worth the ceremony for one boundary-validated invariant).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnmpV3Credentials {
    pub user: String,
    pub auth: Option<SnmpV3AuthCreds>,
    pub priv_: Option<SnmpV3PrivCreds>,
}

/// How to authenticate to a device over SNMP — replaces the former flat
/// `snmp_version`/`snmp_community` pair on [`DeviceTarget`]/[`SnmpCredentials`]. Introduced
/// 2026-08-29 alongside SNMPv3 support: v1/v2c's "version + community string" shape and v3's
/// "username + USM security level" shape are different enough that folding v3 into
/// `SnmpVersion` as a third variant would've left `snmp_community` meaningless whenever that
/// variant was picked — an invalid state the type system could easily prevent instead.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SnmpAuth {
    Community {
        version: SnmpVersion,
        community: String,
    },
    UsmV3(SnmpV3Credentials),
}

impl Default for SnmpAuth {
    fn default() -> Self {
        SnmpAuth::Community {
            version: SnmpVersion::V2c,
            community: "public".to_string(),
        }
    }
}

impl SnmpAuth {
    /// Trims the free-text identifier a user typed by hand — the community string
    /// (`Community`) or the USM username (`UsmV3`) — never `auth`/`priv_`'s passphrases,
    /// which (like a login password) must stay byte-exact: a stray trailing space there is
    /// as likely to be part of the real secret as an accident, and silently altering it
    /// would make an otherwise-correct passphrase fail SNMP negotiation instead of a clear
    /// validation error. Audit finding 5 (2026-09-20): a copy-pasted community string
    /// picking up a trailing newline/space silently fails every SNMP request against every
    /// device using it, with no validation error at save time to point at why.
    pub fn trim_identifiers(&mut self) {
        match self {
            SnmpAuth::Community { community, .. } => *community = community.trim().to_string(),
            SnmpAuth::UsmV3(creds) => creds.user = creds.user.trim().to_string(),
        }
    }
}

/// Where and how to reach a device over SNMP. Kept separate from [`DeviceFacts`] because
/// it's connection configuration, not something a profile's match expression should see.
///
/// `timeout_ms`/`retries` are load-bearing, not cosmetic — see `discovery-snmp::RealSnmpClient`'s
/// docs for the real hang bug (found live 2026-08-16) that made these mandatory: without an
/// explicit timeout, a request against a silently-unreachable target never returns,
/// permanently consuming a `SnmpPoll` worker. Populated from whichever subnet
/// (`discovery-config-store::SubnetSpec`) the target IP belongs to, falling back to
/// [`default_snmp_timeout_ms`]/[`default_snmp_retries`] when no subnet matches or a
/// subnet leaves them unset (`None` = "use the default").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTarget {
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub auth: SnmpAuth,
    #[serde(default = "default_snmp_timeout_ms")]
    pub timeout_ms: u64,
    /// Additional attempts after the first failure — total attempts made is `1 + retries`.
    #[serde(default = "default_snmp_retries")]
    pub retries: u32,
}

/// 2s — a common default among SNMP tooling (e.g. net-snmp's own default), short enough
/// that a dead address in a subnet sweep doesn't stall a worker for long, long enough that
/// a real device under load has a fair chance to answer.
pub fn default_snmp_timeout_ms() -> u64 {
    2000
}

/// One retry (two attempts total) — enough to absorb a single dropped UDP packet (SNMP
/// runs over UDP, no delivery guarantee) without doubling worst-case latency too far.
pub fn default_snmp_retries() -> u32 {
    1
}

impl Default for DeviceTarget {
    fn default() -> Self {
        Self {
            ip: String::new(),
            port: 161,
            auth: SnmpAuth::default(),
            timeout_ms: default_snmp_timeout_ms(),
            retries: default_snmp_retries(),
        }
    }
}

/// SNMP credentials that worked, once — negotiated by trying the candidates
/// (`discovery_core::SnmpAuth` — community or USM v3) configured on whichever subnet
/// (`discovery-config-store::SubnetSpec`) the device's IP belongs to (see
/// `discovery_agent::discovery_scan::negotiate_snmp_credentials`), then recorded here so
/// every later poll uses them directly instead of re-negotiating from scratch every cycle.
/// Mirrors `read_community`/`snmp_version` on ЭРТелеком's `aggregate.devices` table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnmpCredentials {
    #[serde(default)]
    pub auth: SnmpAuth,
    /// Negotiated alongside `auth` from the subnet's `SubnetSpec::port` (default 161) —
    /// not just a UDP-port curiosity: it's what makes local testing against a non-root
    /// SNMP simulator (`snmpd` bound to a high port, e.g. 1161) possible without ever
    /// needing root for a privileged port bind.
    #[serde(default = "default_snmp_port")]
    pub port: u16,
}

fn default_snmp_port() -> u16 {
    161
}

/// How to authenticate to a device over SSH — added 2026-09-07 alongside the SSH CLI-pull
/// metric source (see `discovery_dsl::MetricSpec::SshCommand`'s docs for the feature this
/// exists for: "Config backup/compliance → метрики через SSH CLI pull",
/// `docs/Roadmap.md`). Password or private key (optionally passphrase-protected).
///
/// **Deliberately no plaintext-ok variant, unlike [`SnmpAuth::Community`].** An SNMP
/// community string has a legitimate "not really a secret" mode this codebase already
/// treats as such; there is no SSH equivalent — a login password or a private key are both
/// meaningfully sensitive regardless of which one an operator picks. Both branches always
/// go through at-rest encryption (`discovery_core::secret::encrypt_ssh_auth_secrets`/
/// `decrypt_ssh_auth_secrets`), never a passthrough case the way `Community` gets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SshAuth {
    Password {
        password: String,
    },
    /// `private_key` is the key's full PEM/OpenSSH-format text content, not a filesystem
    /// path — this project has no notion of "a file that happens to live on whichever
    /// agent host runs the poll", only values it stores itself, same as every other
    /// credential here. `passphrase` decrypts the key itself if it's passphrase-protected;
    /// `None` for an unencrypted key.
    PrivateKey {
        private_key: String,
        #[serde(default)]
        passphrase: Option<String>,
    },
}

/// SSH credentials for one device — the SSH counterpart of [`SnmpCredentials`], with one
/// load-bearing difference: **manual-entry-only**, never auto-negotiated. `SnmpCredentials`
/// gets discovered by trying a short list of community strings/USM users a subnet declares
/// as candidates (`discovery_agent::discovery_scan::negotiate_snmp_credentials`); there is
/// no SSH equivalent of that — a username/password or private key isn't something safe (or
/// even generally possible) to brute-force-probe across a subnet the way a handful of
/// conventional community strings is. An operator sets this explicitly, per device, via
/// `POST /api/devices`/a dedicated `PUT` endpoint (see `discovery-web`'s device handlers) —
/// there is no discovery-pipeline code path that ever writes this on its own.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshCredentials {
    pub username: String,
    pub auth: SshAuth,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// SHA256 fingerprint of this device's trusted SSH host key (OpenSSH `SHA256:<base64>`
    /// format — what `ssh-keygen -lf`/`ssh`'s own connection banner print), closing the
    /// CWE-295 gap `discovery_ssh::client::Handler::check_server_key` originally
    /// documented as a deliberate v1 scope cut ("accepts every server key unconditionally
    /// ... revisit with host-key pinning ... if that ever becomes a real deployment
    /// scenario").
    ///
    /// `None` = not yet pinned: trust-on-first-use, mirroring how `ssh` itself populates
    /// `known_hosts` on a first connection — `discovery_ssh::RealCliClient::exec` accepts
    /// whatever key the server presents on that connection and reports it back
    /// (`SshExecOutcome::newly_pinned_host_key`) so `MetricPollHandler` can persist it via
    /// `DeviceStore::pin_ssh_host_key`. `Some(fp)` = pinned: every subsequent connection's
    /// presented key must hash to exactly this fingerprint or the connection is refused
    /// before authentication is ever attempted — a mismatch means either the device's host
    /// key legitimately rotated or a MITM is presenting a different key, and there is no
    /// way to tell those apart automatically, so this always fails closed rather than
    /// silently re-pinning. `PUT /api/devices/:id/ssh_credentials` always resets this back
    /// to `None` (rotating credentials is already a deliberate manual action; an operator
    /// who legitimately rotated a device's host key alongside its credentials gets a fresh
    /// TOFU pin on the very next connection instead of a permanent lockout).
    #[serde(default)]
    pub known_host_key: Option<String>,
}

pub fn default_ssh_port() -> u16 {
    22
}

/// Where and how to reach a device over SSH for one `MetricSpec::SshCommand` poll — the SSH
/// counterpart of [`DeviceTarget`]. **No `retries` field**, unlike `DeviceTarget`'s
/// SNMP-over-UDP retry loop: SSH runs over TCP with connection/auth-level error semantics,
/// so a failed connect/authenticate/exec reliably means "this will fail again the exact
/// same way" (wrong password, host unreachable, command not found), not "one UDP packet
/// got silently dropped" — blindly retrying would just double the latency of an attempt
/// that's already going to fail the same way, see `discovery-ssh::RealCliClient`'s docs.
/// `timeout` is likewise not stored here — it's passed as its own parameter to
/// `discovery_ssh::CliClient::exec`, mirroring `discovery_ping::Pinger::ping`'s convention
/// (caller-supplied per call) rather than `DeviceTarget`'s (baked into the struct, an
/// earlier convention this project used before `Pinger` established the newer one).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshTarget {
    pub ip: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    /// Pass-through of [`SshCredentials::known_host_key`] — see its docs for the
    /// trust-on-first-use/pin-then-verify contract `discovery_ssh::client::Handler`
    /// enforces against this field.
    pub known_host_key: Option<String>,
}

/// A device known to the system: its facts, and (once matched) the profile driving how
/// it gets configured and polled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: uuid::Uuid,
    pub facts: DeviceFacts,
    pub profile: Option<String>,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
    /// `None` until `SnmpPoll` successfully negotiates working credentials for this
    /// device (or forever `None` if its IP doesn't fall inside any configured subnet —
    /// callers then fall back to `DeviceTarget::default()`, same as before this existed).
    pub snmp_credentials: Option<SnmpCredentials>,
    /// **Live reachability status — deliberately separate from everything above.**
    /// `snmp_credentials` records *what worked once* (negotiated version/community/port);
    /// these four fields record *is it answering right now*, refreshed on its own
    /// recurring cadence (`QueueKind::ReachabilityPoll`, independent of profile matching —
    /// runs even for devices that never matched any profile). Not part of `Metrics`/
    /// `device_metrics` either: the user was explicit that this is "ещё одна колонка на
    /// дашборд, помимо других метрик, но эта колонка будет в отдельном поле" — a
    /// device-level fact, not something a profile or dedup/match expression should see.
    ///
    /// `None` = never checked yet (device just created, the reachability chain hasn't had
    /// its first tick). `Some(true)`/`Some(false)` = last check's outcome, paired with the
    /// `*_checked_at` timestamp of that check.
    #[serde(default)]
    pub ping_ok: Option<bool>,
    #[serde(default)]
    pub ping_checked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The share of the most recent reachability tick's `1 + retries` ICMP attempts that
    /// got no reply, `0.0`-`100.0` — added 2026-09-14, `docs/Roadmap.md` "До релиза" item
    /// 5 ("Packet loss % не собирается вообще"), a direct honest-porting prerequisite for
    /// AggreGate's ICMP-packet-loss alert. `None` until the first reachability tick after
    /// this field existed, same convention as `ping_ok`/`ping_checked_at` themselves —
    /// see `discovery_ping::PingOutcome`'s docs for why this needs every attempt to
    /// actually run (no more stopping at the first success).
    #[serde(default)]
    pub ping_loss_pct: Option<f64>,
    /// `Some(false)` immediately (no network I/O) if `snmp_credentials` is still `None` —
    /// there's nothing to poll with yet. Once credentials exist, this is a lightweight
    /// `GET` on `sysUpTime`, not a full profile re-poll.
    #[serde(default)]
    pub snmp_ok: Option<bool>,
    #[serde(default)]
    pub snmp_checked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the *current, unbroken* run of `ping_ok = false` started — `None` whenever
    /// `ping_ok` is `true` or has never been checked. Added 2026-08-18, direct user
    /// request: "настраиваемый через конфиг период времени после которого устройство с
    /// ping=false удаляется" — this is what lets the cleanup sweep
    /// (`DeviceStore::delete_unreachable_since`) tell "been down for the configured
    /// threshold" apart from "went down once, five minutes ago, and is fine again now".
    /// Set/cleared atomically by [`Self`]-implementing stores inside `set_reachability`
    /// itself (comparing the *new* `ping_ok` against whatever was already on the row) —
    /// never computed by `ReachabilityPollHandler`, which only ever sees the latest single
    /// check and has no memory of the previous one.
    #[serde(default)]
    pub ping_failing_since: Option<chrono::DateTime<chrono::Utc>>,
    /// Device-level master switch — direct user request 2026-08-16: "мне нужна
    /// возможность выключать устройства (выключить все)". `false` means
    /// `MetricPollHandler`/`ReachabilityPollHandler` skip all actual polling work for this
    /// device on every tick, though the recurring chain itself keeps running (so
    /// re-enabling applies on the very next tick, no restart/re-discovery needed) — see
    /// each handler's docs. Identity polling (`SnmpPoll`) is deliberately unaffected.
    /// Defaults to `true` — a freshly discovered device is enabled until told otherwise.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `None` until an operator manually configures SSH credentials for this device — see
    /// [`SshCredentials`]'s docs for why this is never auto-negotiated the way
    /// `snmp_credentials` is. `discovery_agent::handlers::MetricPollHandler` needs this to
    /// poll any `discovery_dsl::MetricSpec::SshCommand` metric a device's profile declares;
    /// a due SSH-command metric on a device with no credentials configured simply fails
    /// that one poll with an explanatory error (`MetricPollOutcome::Err`), the same
    /// "nothing to poll with yet" outcome an SNMP metric gets on a device that hasn't
    /// completed its first `SnmpPoll` negotiation.
    #[serde(default)]
    pub ssh_credentials: Option<SshCredentials>,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_target_default_is_snmp_v2c_on_port_161() {
        let target = DeviceTarget::default();
        assert_eq!(target.port, 161);
        assert_eq!(
            target.auth,
            SnmpAuth::Community {
                version: SnmpVersion::V2c,
                community: "public".to_string()
            }
        );
    }

    #[test]
    fn snmp_auth_community_round_trips_through_json() {
        let auth = SnmpAuth::Community {
            version: SnmpVersion::V1,
            community: "private".to_string(),
        };
        let json = serde_json::to_string(&auth).unwrap();
        let back: SnmpAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(auth, back);
    }

    #[test]
    fn snmp_auth_usm_v3_auth_priv_round_trips_through_json() {
        let auth = SnmpAuth::UsmV3(SnmpV3Credentials {
            user: "monitor".to_string(),
            auth: Some(SnmpV3AuthCreds {
                protocol: SnmpAuthProtocol::Sha1,
                passphrase: "authpass123".to_string(),
            }),
            priv_: Some(SnmpV3PrivCreds {
                protocol: SnmpPrivProtocol::Aes128,
                passphrase: "privpass123".to_string(),
            }),
        });
        let json = serde_json::to_string(&auth).unwrap();
        let back: SnmpAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(auth, back);
    }

    #[test]
    fn snmp_auth_usm_v3_no_auth_no_priv_round_trips_through_json() {
        let auth = SnmpAuth::UsmV3(SnmpV3Credentials {
            user: "readonly".to_string(),
            auth: None,
            priv_: None,
        });
        let json = serde_json::to_string(&auth).unwrap();
        let back: SnmpAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(auth, back);
    }

    #[test]
    fn ssh_auth_password_round_trips_through_json() {
        let auth = SshAuth::Password {
            password: "hunter2".to_string(),
        };
        let json = serde_json::to_string(&auth).unwrap();
        let back: SshAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(auth, back);
    }

    #[test]
    fn ssh_auth_private_key_round_trips_through_json_with_and_without_passphrase() {
        let with_pass = SshAuth::PrivateKey {
            private_key: "-----BEGIN KEY-----".to_string(),
            passphrase: Some("secret".to_string()),
        };
        let json = serde_json::to_string(&with_pass).unwrap();
        assert_eq!(serde_json::from_str::<SshAuth>(&json).unwrap(), with_pass);

        let no_pass = SshAuth::PrivateKey {
            private_key: "-----BEGIN KEY-----".to_string(),
            passphrase: None,
        };
        let json = serde_json::to_string(&no_pass).unwrap();
        assert_eq!(serde_json::from_str::<SshAuth>(&json).unwrap(), no_pass);
    }

    #[test]
    fn ssh_credentials_missing_port_defaults_to_22() {
        let json = r#"{"username": "admin", "auth": {"kind": "password", "password": "x"}}"#;
        let creds: SshCredentials = serde_json::from_str(json).unwrap();
        assert_eq!(creds.port, 22);
    }

    #[test]
    fn ssh_credentials_missing_known_host_key_defaults_to_none() {
        let json = r#"{"username": "admin", "auth": {"kind": "password", "password": "x"}}"#;
        let creds: SshCredentials = serde_json::from_str(json).unwrap();
        assert_eq!(
            creds.known_host_key, None,
            "old-shape JSON predating host-key pinning must deserialize as unpinned, not fail"
        );
    }

    #[test]
    fn ssh_credentials_known_host_key_round_trips_through_json() {
        let creds = SshCredentials {
            username: "admin".to_string(),
            auth: SshAuth::Password {
                password: "hunter2".to_string(),
            },
            port: 22,
            known_host_key: Some("SHA256:abc123".to_string()),
        };
        let json = serde_json::to_string(&creds).unwrap();
        let back: SshCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(creds, back);
    }

    #[test]
    fn device_target_missing_auth_field_deserializes_to_default() {
        // Old-shape JSON (pre-`SnmpAuth`, if any lingers in a stored config/test fixture)
        // has no `auth` field at all — must not fail to deserialize, must fall back to
        // `SnmpAuth::default()` the same way `timeout_ms`/`retries` already do.
        let json = r#"{"ip":"10.0.0.1","port":161,"timeout_ms":2000,"retries":1}"#;
        let target: DeviceTarget = serde_json::from_str(json).unwrap();
        assert_eq!(target.auth, SnmpAuth::default());
    }
}
