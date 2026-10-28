use std::collections::HashMap;

use chrono::{DateTime, Utc};
use discovery_core::Domain;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Classic read/write — "чтение, запись, для различных доменов" (direct user request).
/// `Write` implies `Read` (see [`AccessLevel::satisfies`]) — there is no separate
/// standalone "read" grant a `Write` holder is missing. No "no access" variant: absence of
/// a domain from a user's permission map already means "no access" (see
/// [`crate::AuthStore::permissions_for`]'s docs) — an explicit `None` level would be a
/// second way to say the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessLevel {
    Read,
    Write,
}

impl AccessLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessLevel::Read => "read",
            AccessLevel::Write => "write",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "read" => AccessLevel::Read,
            "write" => AccessLevel::Write,
            _ => return None,
        })
    }

    /// Whether holding `self` is enough to satisfy a `required` check — `Write` satisfies
    /// both `Write` and `Read` requirements; `Read` only satisfies `Read`.
    pub fn satisfies(&self, required: AccessLevel) -> bool {
        match required {
            AccessLevel::Read => true,
            AccessLevel::Write => matches!(self, AccessLevel::Write),
        }
    }
}

/// A named, reusable per-domain permission bundle (2026-08-27, design-artifact parity
/// pass, round 5: "система не имеет фиксированной роли, только именованные списки
/// доступа" — introduced a proper Roles model; a user just picks one from a dropdown,
/// doesn't set per-domain permissions directly). Replaces the earlier flat per-user
/// `user_permissions` table entirely — see [`crate::AuthStore`]'s docs for the full
/// rationale. `permissions` uses the same "absence = no access" convention the old
/// per-user table did, just one level of indirection further out: a domain missing from
/// this map means no role member gets access to it at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub permissions: HashMap<Domain, AccessLevel>,
}

/// A local account. Deliberately carries no password hash — see
/// `discovery_auth::AuthStore`'s docs for why that's never handed back to a caller as part
/// of this struct (it's an implementation detail of `verify_password`/`set_password`
/// alone), which also makes this the safe shape to serialize straight into a REST
/// response (`GET /api/users`) without an allow-list of fields to strip first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    /// Bypasses every per-domain check in [`AuthenticatedUser::can`] entirely — user/
    /// permission management itself needs its own elevated right, distinct from the 8
    /// business domains (see `discovery/CLAUDE.md`'s AggreGate auth survey on why even
    /// AggreGate keeps role/permission administration separate from object-level ACL).
    pub is_admin: bool,
    /// Forces the account through `PUT /api/auth/password` before it can do anything else
    /// (added 2026-08-26, direct user request: the first-run bootstrap account ships with
    /// a fixed, publicly-known `admin`/`admin` login — see `discovery-agent::main`'s
    /// docs — specifically so a real end customer isn't handed a secret to safeguard on
    /// day one; this flag is what makes that safe instead of a standing open door).
    /// `discovery-web`'s `require_domain_permission`/`require_admin` middleware reject
    /// every domain/admin-gated request while this is `true` — the server enforces it,
    /// not just the dashboard UI. Cleared automatically by [`crate::AuthStore::set_password`]
    /// (self-service change or an admin's reset both count as "no longer using a
    /// standing default/temporary password").
    pub must_change_password: bool,
    /// Which [`Role`] (if any) this account's domain permissions come from. `None` = no
    /// role assigned, i.e. no domain access at all (same "absence = no access"
    /// convention `Role::permissions` itself uses one level down) — same meaning `is_admin
    /// = false` + no `user_permissions` row used to have, before roles replaced that
    /// table. Doesn't bypass `is_admin`: an admin's `role_id` is irrelevant to what they
    /// can do (see [`AuthenticatedUser::can`]), only tracked here for the dashboard's own
    /// "which role is this admin nominally assigned" display.
    pub role_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// The result of resolving a session token — everything a request handler/middleware
/// needs to decide "is this request allowed", already joined (user + permissions) so
/// `discovery-web`'s auth middleware is a single [`crate::AuthStore::authenticate_session`]
/// call, not a user lookup followed by a separate permissions lookup.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: Uuid,
    pub username: String,
    pub is_admin: bool,
    /// See [`User::must_change_password`]'s docs — carried through here so the auth
    /// middleware can reject on it without a second `AuthStore` round trip.
    pub must_change_password: bool,
    /// See [`User::role_id`]'s docs — carried through here too, same reason
    /// `must_change_password` is.
    pub role_id: Option<Uuid>,
    /// Resolved from `role_id`'s [`Role::permissions`] at session-authentication time —
    /// empty if `role_id` is `None` or the role no longer exists (e.g. deleted out from
    /// under an already-issued session; that session simply loses domain access on its
    /// very next request, same as `is_admin` being revoked would).
    pub permissions: HashMap<Domain, AccessLevel>,
}

impl AuthenticatedUser {
    /// `is_admin` short-circuits to "always allowed" — see [`User::is_admin`]'s docs.
    /// Otherwise, a domain absent from `permissions` means no access at all (same
    /// "absence = default" convention `discovery_queue`'s `queue_control` already uses).
    pub fn can(&self, domain: Domain, required: AccessLevel) -> bool {
        self.is_admin
            || self
                .permissions
                .get(&domain)
                .is_some_and(|level| level.satisfies(required))
    }
}
