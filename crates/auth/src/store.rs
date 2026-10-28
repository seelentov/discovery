use std::collections::HashMap;

use async_trait::async_trait;
use discovery_core::Domain;
use uuid::Uuid;

use crate::{AccessLevel, AuthenticatedUser, Role, User};

/// Local users, sessions, roles, and per-role permissions — one trait for all of it
/// (matching this project's usual "one store trait per crate" shape, e.g.
/// `JobQueueStore`) because they're only ever meaningful together: a session resolves to
/// a user, a user's assigned role gates what that session can do. One implementation —
/// [`crate::SeaOrmAuthStore`].
#[async_trait]
pub trait AuthStore: Send + Sync {
    /// Creates a new local user with the given role (or `None` — no domain access yet).
    /// Hashes `password` internally — callers never handle a password hash directly.
    /// Errors (not silently overwrites) if `username` is already taken — same "let the
    /// caller see the conflict" discipline as
    /// `discovery_config_store::ProfileStore::upsert`'s uniqueness checks elsewhere in
    /// this project.
    ///
    /// `must_change_password` — see [`User::must_change_password`]'s docs. `true` for the
    /// first-run bootstrap account (fixed `admin`/`admin`); `false` for everything else
    /// unless the caller (e.g. `POST /api/users`) explicitly opts a new account into the
    /// same forced-change flow.
    async fn create_user(
        &self,
        username: &str,
        password: &str,
        is_admin: bool,
        must_change_password: bool,
        role_id: Option<Uuid>,
    ) -> anyhow::Result<User>;

    async fn get_user_by_id(&self, id: Uuid) -> anyhow::Result<Option<User>>;

    async fn list_users(&self) -> anyhow::Result<Vec<User>>;

    /// Deletes the user outright — cascades to their sessions and permissions (real DB-
    /// level `ON DELETE CASCADE` FKs, `users`/`sessions`/`user_permissions` always share
    /// one connection by construction, unlike the cross-domain device/alert FKs elsewhere
    /// in this project). Returns `false` if no such user existed.
    async fn delete_user(&self, id: Uuid) -> anyhow::Result<bool>;

    /// Returns `false` if no such user existed. Also clears [`User::must_change_password`]
    /// unconditionally — whether this was a self-service change (`PUT /api/auth/password`)
    /// or an admin's reset (`PUT /api/users/:id/password`), the account now has a password
    /// only it (or the admin who just set it) knows, which is exactly the condition that
    /// flag exists to track. A caller that wants the *new* password to itself be temporary
    /// (e.g. an admin deliberately resetting to something the user must change again) sets
    /// the flag back with a dedicated call — there is no such call yet, since nothing in
    /// this project needs it; add one rather than skip this reset if that need shows up.
    async fn set_password(&self, id: Uuid, new_password: &str) -> anyhow::Result<bool>;

    /// Returns `false` if no such user existed.
    async fn set_admin(&self, id: Uuid, is_admin: bool) -> anyhow::Result<bool>;

    /// Checks `username`/`password` and, on success, returns that user — `None` for *any*
    /// failure (wrong username, wrong password, no such user), on purpose: distinguishing
    /// "no such user" from "wrong password" in the response is a username-enumeration
    /// oracle, so both collapse to the same `None` here rather than leaving that judgment
    /// call to every caller individually.
    async fn verify_password(&self, username: &str, password: &str)
        -> anyhow::Result<Option<User>>;

    /// How many local users exist — used only for first-run bootstrap (see
    /// `discovery-agent::main`'s docs): an empty `users` table on startup means no admin
    /// can possibly log in yet, so one is created automatically.
    async fn user_count(&self) -> anyhow::Result<u64>;

    /// Assigns (or clears, with `None`) which role gates this user's domain access — see
    /// [`User::role_id`]'s docs. Returns `false` if no such user existed. Does **not**
    /// validate that `role_id` refers to an existing role — same "caller's job, not the
    /// store's" contract `discovery_config_store` uses for cross-domain FK-shaped
    /// references (a dangling `role_id` just resolves to "no permissions" at
    /// authentication time, exactly like a deleted role would, rather than needing a
    /// second failure mode here).
    async fn set_user_role(&self, user_id: Uuid, role_id: Option<Uuid>) -> anyhow::Result<bool>;

    /// Creates a new role with the given per-domain permission set. Errors if `name` is
    /// already taken — same discipline as [`Self::create_user`]'s username check.
    async fn create_role(
        &self,
        name: &str,
        permissions: HashMap<Domain, AccessLevel>,
    ) -> anyhow::Result<Role>;

    async fn list_roles(&self) -> anyhow::Result<Vec<Role>>;

    async fn get_role(&self, id: Uuid) -> anyhow::Result<Option<Role>>;

    /// Renames the role and **replaces its entire permission set** (not a merge — a
    /// domain left out of `permissions` ends up with no access under this role, same as
    /// if it had never been granted). Returns `false` if no such role existed.
    async fn update_role(
        &self,
        id: Uuid,
        name: &str,
        permissions: HashMap<Domain, AccessLevel>,
    ) -> anyhow::Result<bool>;

    /// Deletes the role outright — cascades to its own `role_permissions` rows (real
    /// DB-level `ON DELETE CASCADE`) and unassigns (`SET NULL`, not cascading delete) every
    /// user who had it, see `discovery_migration`'s `up()` docs for the FK shape. Returns
    /// `false` if no such role existed.
    async fn delete_role(&self, id: Uuid) -> anyhow::Result<bool>;

    /// Issues a new session for an already-authenticated user (see
    /// [`Self::verify_password`]) and returns the **raw** token — the only place the raw
    /// value ever exists outside the client's own cookie/header, since the store only
    /// persists its hash (see `discovery_migration`'s `sessions` docs).
    async fn create_session(&self, user_id: Uuid, ttl: chrono::Duration) -> anyhow::Result<String>;

    /// Resolves a raw token (as presented by a client) to the user + permissions it
    /// authenticates, or `None` if the token is unknown, expired, or its user no longer
    /// exists. One call for `discovery-web`'s auth middleware to make per request — no
    /// separate "look up session" then "look up user" then "look up permissions" round
    /// trips.
    async fn authenticate_session(
        &self,
        raw_token: &str,
    ) -> anyhow::Result<Option<AuthenticatedUser>>;

    /// Logout — deletes one session by its raw token. Not an error if it was already gone
    /// (already logged out / expired and reaped) — same idempotent-delete convention as
    /// `discovery_queue::JobQueueStore::delete_job`.
    async fn delete_session(&self, raw_token: &str) -> anyhow::Result<()>;

    /// Revokes every session belonging to a user. Password changes and administrator
    /// resets use this as a security boundary: an already-issued seven-day token must not
    /// remain a valid credential after the password it represents has changed.
    async fn delete_sessions_for_user(&self, user_id: Uuid) -> anyhow::Result<u64>;

    /// Reaps expired sessions — a housekeeping sweep, not something request handling
    /// depends on for correctness (`authenticate_session` already checks `expires_at`
    /// itself on every call), same relationship `JobQueueStore::reclaim_stale` has to
    /// `claim`. Returns how many rows were deleted.
    async fn delete_expired_sessions(&self) -> anyhow::Result<u64>;
}
