use std::collections::HashMap;

use async_trait::async_trait;
use chrono::Utc;
use discovery_core::Domain;
use discovery_entities::role_permissions::{
    ActiveModel as RolePermActiveModel, Column as RolePermColumn, Entity as RolePermEntity,
};
use discovery_entities::roles::{
    ActiveModel as RoleActiveModel, Column as RoleColumn, Entity as RoleEntity, Model as RoleModel,
};
use discovery_entities::sessions::{
    ActiveModel as SessionActiveModel, Column as SessionColumn, Entity as SessionEntity,
};
use discovery_entities::users::{
    ActiveModel as UserActiveModel, Column as UserColumn, Entity as UserEntity, Model as UserModel,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter,
};
use uuid::Uuid;

use crate::{
    hash_password, hash_token, verify_password as check_password, AccessLevel, AuthStore,
    AuthenticatedUser, Role, User,
};

fn model_to_user(m: UserModel) -> User {
    User {
        id: m.id,
        username: m.username,
        is_admin: m.is_admin,
        must_change_password: m.must_change_password,
        role_id: m.role_id,
        created_at: m.created_at,
    }
}

/// A real Argon2id hash of a fixed, non-secret placeholder — checked against on every
/// login attempt for a username that doesn't exist (SEC-20, 2026-09-22), purely to make
/// "no such user" cost the same CPU time as "wrong password for a real user". Without
/// this, `verify_password` below would return early on a missing row without ever running
/// Argon2id, and Argon2id's deliberately-expensive verify (tens of ms) dwarfs an indexed
/// username lookup (sub-ms) — a difference easily measurable over the network, letting an
/// attacker enumerate valid usernames from response timing alone even though both cases
/// already return the identical `"invalid username or password"` message. `LazyLock`, not
/// `const`, because Argon2's own salt generation makes a compile-time hash impossible;
/// computed once, on first use, not per request.
static DUMMY_PASSWORD_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    hash_password("sec-20-timing-equalizer-not-a-real-account-password")
        .expect("hashing a fixed literal cannot fail")
});

/// The sea-orm-backed implementation, following the same one-store-per-crate,
/// Postgres/MySQL/SQLite-through-one-code-path shape as every other store in this project
/// (e.g. `discovery_queue::SeaOrmJobQueueStore`).
pub struct SeaOrmAuthStore {
    db: DatabaseConnection,
}

impl SeaOrmAuthStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn new_in_memory_for_tests() -> Self {
        Self::new(discovery_migration::connect_in_memory_for_tests().await)
    }

    /// Shared by [`AuthStore::list_roles`]/[`AuthStore::get_role`] — one role's row plus
    /// its permission set, joined the same "load once, filter in Rust" way
    /// `discovery-web`'s `build_device_views` resolves each device's profile.
    async fn role_from_model(&self, model: RoleModel) -> anyhow::Result<Role> {
        let permissions = self.permissions_for_role(model.id).await?;
        Ok(Role {
            id: model.id,
            name: model.name,
            permissions,
        })
    }

    async fn permissions_for_role(
        &self,
        role_id: Uuid,
    ) -> anyhow::Result<HashMap<Domain, AccessLevel>> {
        let rows = RolePermEntity::find()
            .filter(RolePermColumn::RoleId.eq(role_id))
            .all(&self.db)
            .await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                Some((
                    Domain::from_str(&r.domain)?,
                    AccessLevel::from_str(&r.level)?,
                ))
            })
            .collect())
    }
}

#[async_trait]
impl AuthStore for SeaOrmAuthStore {
    async fn create_user(
        &self,
        username: &str,
        password: &str,
        is_admin: bool,
        must_change_password: bool,
        role_id: Option<Uuid>,
    ) -> anyhow::Result<User> {
        if UserEntity::find()
            .filter(UserColumn::Username.eq(username))
            .one(&self.db)
            .await?
            .is_some()
        {
            anyhow::bail!("username '{username}' is already taken");
        }
        let am = UserActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(username.to_string()),
            password_hash: Set(hash_password(password)?),
            is_admin: Set(is_admin),
            must_change_password: Set(must_change_password),
            role_id: Set(role_id),
            created_at: Set(Utc::now()),
        };
        Ok(model_to_user(am.insert(&self.db).await?))
    }

    async fn get_user_by_id(&self, id: Uuid) -> anyhow::Result<Option<User>> {
        Ok(UserEntity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(model_to_user))
    }

    async fn list_users(&self) -> anyhow::Result<Vec<User>> {
        Ok(UserEntity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(model_to_user)
            .collect())
    }

    async fn delete_user(&self, id: Uuid) -> anyhow::Result<bool> {
        Ok(UserEntity::delete_by_id(id)
            .exec(&self.db)
            .await?
            .rows_affected
            > 0)
    }

    async fn set_password(&self, id: Uuid, new_password: &str) -> anyhow::Result<bool> {
        let Some(model) = UserEntity::find_by_id(id).one(&self.db).await? else {
            return Ok(false);
        };
        let mut am: UserActiveModel = model.into();
        am.password_hash = Set(hash_password(new_password)?);
        am.must_change_password = Set(false);
        am.update(&self.db).await?;
        Ok(true)
    }

    async fn set_admin(&self, id: Uuid, is_admin: bool) -> anyhow::Result<bool> {
        let Some(model) = UserEntity::find_by_id(id).one(&self.db).await? else {
            return Ok(false);
        };
        let mut am: UserActiveModel = model.into();
        am.is_admin = Set(is_admin);
        am.update(&self.db).await?;
        Ok(true)
    }

    async fn verify_password(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Option<User>> {
        let Some(model) = UserEntity::find()
            .filter(UserColumn::Username.eq(username))
            .one(&self.db)
            .await?
        else {
            // Pays the same Argon2id cost a real user's rejection would — see
            // `DUMMY_PASSWORD_HASH`'s docs. The result is discarded: it's always `false`
            // (this hash matches no real login), only the CPU time spent matters.
            check_password(password, &DUMMY_PASSWORD_HASH);
            return Ok(None);
        };
        if !check_password(password, &model.password_hash) {
            return Ok(None);
        }
        Ok(Some(model_to_user(model)))
    }

    async fn user_count(&self) -> anyhow::Result<u64> {
        Ok(UserEntity::find().count(&self.db).await?)
    }

    async fn set_user_role(&self, user_id: Uuid, role_id: Option<Uuid>) -> anyhow::Result<bool> {
        let Some(model) = UserEntity::find_by_id(user_id).one(&self.db).await? else {
            return Ok(false);
        };
        let mut am: UserActiveModel = model.into();
        am.role_id = Set(role_id);
        am.update(&self.db).await?;
        Ok(true)
    }

    async fn create_role(
        &self,
        name: &str,
        permissions: HashMap<Domain, AccessLevel>,
    ) -> anyhow::Result<Role> {
        if RoleEntity::find()
            .filter(RoleColumn::Name.eq(name))
            .one(&self.db)
            .await?
            .is_some()
        {
            anyhow::bail!("role '{name}' is already taken");
        }
        let id = Uuid::new_v4();
        let am = RoleActiveModel {
            id: Set(id),
            name: Set(name.to_string()),
        };
        am.insert(&self.db).await?;
        for (domain, level) in &permissions {
            let perm = RolePermActiveModel {
                role_id: Set(id),
                domain: Set(domain.as_str().to_string()),
                level: Set(level.as_str().to_string()),
            };
            perm.insert(&self.db).await?;
        }
        Ok(Role {
            id,
            name: name.to_string(),
            permissions,
        })
    }

    async fn list_roles(&self) -> anyhow::Result<Vec<Role>> {
        let models = RoleEntity::find().all(&self.db).await?;
        let mut roles = Vec::with_capacity(models.len());
        for model in models {
            roles.push(self.role_from_model(model).await?);
        }
        Ok(roles)
    }

    async fn get_role(&self, id: Uuid) -> anyhow::Result<Option<Role>> {
        match RoleEntity::find_by_id(id).one(&self.db).await? {
            Some(model) => Ok(Some(self.role_from_model(model).await?)),
            None => Ok(None),
        }
    }

    async fn update_role(
        &self,
        id: Uuid,
        name: &str,
        permissions: HashMap<Domain, AccessLevel>,
    ) -> anyhow::Result<bool> {
        let Some(model) = RoleEntity::find_by_id(id).one(&self.db).await? else {
            return Ok(false);
        };
        if RoleEntity::find()
            .filter(RoleColumn::Name.eq(name))
            .filter(RoleColumn::Id.ne(id))
            .one(&self.db)
            .await?
            .is_some()
        {
            anyhow::bail!("role '{name}' is already taken");
        }
        let mut am: RoleActiveModel = model.into();
        am.name = Set(name.to_string());
        am.update(&self.db).await?;

        // Full-replace, not a merge — see `AuthStore::update_role`'s docs. Delete every
        // existing row for this role, then insert exactly what's asked for now.
        RolePermEntity::delete_many()
            .filter(RolePermColumn::RoleId.eq(id))
            .exec(&self.db)
            .await?;
        for (domain, level) in &permissions {
            let perm = RolePermActiveModel {
                role_id: Set(id),
                domain: Set(domain.as_str().to_string()),
                level: Set(level.as_str().to_string()),
            };
            perm.insert(&self.db).await?;
        }
        Ok(true)
    }

    async fn delete_role(&self, id: Uuid) -> anyhow::Result<bool> {
        Ok(RoleEntity::delete_by_id(id)
            .exec(&self.db)
            .await?
            .rows_affected
            > 0)
    }

    async fn create_session(&self, user_id: Uuid, ttl: chrono::Duration) -> anyhow::Result<String> {
        let raw_token = crate::generate_token();
        let now = Utc::now();
        let am = SessionActiveModel {
            token_hash: Set(hash_token(&raw_token)),
            user_id: Set(user_id),
            created_at: Set(now),
            expires_at: Set(now + ttl),
        };
        am.insert(&self.db).await?;
        Ok(raw_token)
    }

    async fn authenticate_session(
        &self,
        raw_token: &str,
    ) -> anyhow::Result<Option<AuthenticatedUser>> {
        let Some(session) = SessionEntity::find_by_id(hash_token(raw_token))
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };
        if session.expires_at < Utc::now() {
            return Ok(None);
        }
        let Some(user) = UserEntity::find_by_id(session.user_id)
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };
        // A dangling `role_id` (role deleted out from under this user) resolves to no
        // permissions, same as `role_id: None` — see `AuthStore::set_user_role`'s docs.
        let permissions = match user.role_id {
            Some(role_id) => self.permissions_for_role(role_id).await?,
            None => HashMap::new(),
        };
        Ok(Some(AuthenticatedUser {
            id: user.id,
            username: user.username,
            is_admin: user.is_admin,
            must_change_password: user.must_change_password,
            role_id: user.role_id,
            permissions,
        }))
    }

    async fn delete_session(&self, raw_token: &str) -> anyhow::Result<()> {
        SessionEntity::delete_by_id(hash_token(raw_token))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: Uuid) -> anyhow::Result<u64> {
        Ok(SessionEntity::delete_many()
            .filter(SessionColumn::UserId.eq(user_id))
            .exec(&self.db)
            .await?
            .rows_affected)
    }

    async fn delete_expired_sessions(&self) -> anyhow::Result<u64> {
        Ok(SessionEntity::delete_many()
            .filter(SessionColumn::ExpiresAt.lt(Utc::now()))
            .exec(&self.db)
            .await?
            .rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_store() -> SeaOrmAuthStore {
        SeaOrmAuthStore::new_in_memory_for_tests().await
    }

    #[tokio::test]
    async fn create_user_rejects_duplicate_username() {
        let store = test_store().await;
        store
            .create_user("alice", "hunter2", false, false, None)
            .await
            .unwrap();
        let err = store
            .create_user("alice", "different", false, false, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already taken"));
    }

    #[tokio::test]
    async fn verify_password_succeeds_only_for_the_right_username_and_password() {
        let store = test_store().await;
        store
            .create_user("alice", "hunter2", false, false, None)
            .await
            .unwrap();

        assert!(store
            .verify_password("alice", "hunter2")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .verify_password("alice", "wrong")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .verify_password("nobody", "hunter2")
            .await
            .unwrap()
            .is_none());
    }

    /// SEC-20 (2026-09-22) — rejecting an unknown username must cost roughly the same
    /// CPU time as rejecting a wrong password for a real user, or an attacker can
    /// enumerate valid usernames purely from response latency (Argon2id's deliberately
    /// expensive verify vs. an indexed lookup finding no row is a difference of orders of
    /// magnitude, easily measurable over a network). A loose ratio bound, not a tight
    /// equality, because wall-clock timing in a shared CI runner is inherently noisy —
    /// this is calibrated to reliably fail if `verify_password` regresses back to an
    /// early return that skips Argon2id entirely for a missing user (which would make the
    /// unknown-user path faster by roughly two orders of magnitude, not by some jitter-y
    /// 10-20%), not to catch a few percent of drift.
    #[tokio::test]
    async fn unknown_username_and_wrong_password_reject_in_comparable_time() {
        let store = test_store().await;
        store
            .create_user("alice", "hunter2", false, false, None)
            .await
            .unwrap();

        let iterations = 5;
        let mut known_user_wrong_password = std::time::Duration::ZERO;
        let mut unknown_user = std::time::Duration::ZERO;
        for _ in 0..iterations {
            let start = std::time::Instant::now();
            assert!(store
                .verify_password("alice", "wrong-password")
                .await
                .unwrap()
                .is_none());
            known_user_wrong_password += start.elapsed();

            let start = std::time::Instant::now();
            assert!(store
                .verify_password("nobody-with-this-name", "hunter2")
                .await
                .unwrap()
                .is_none());
            unknown_user += start.elapsed();
        }

        assert!(
            unknown_user.as_secs_f64() >= known_user_wrong_password.as_secs_f64() * 0.5,
            "rejecting an unknown username ({unknown_user:?} total) must not be dramatically faster than rejecting a wrong password for a real user ({known_user_wrong_password:?} total) — a large gap means Argon2id is being skipped for missing users again"
        );
    }

    #[tokio::test]
    async fn set_password_changes_which_password_verifies() {
        let store = test_store().await;
        let user = store
            .create_user("alice", "old-password", false, false, None)
            .await
            .unwrap();

        assert!(store.set_password(user.id, "new-password").await.unwrap());
        assert!(store
            .verify_password("alice", "old-password")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .verify_password("alice", "new-password")
            .await
            .unwrap()
            .is_some());

        assert!(
            !store
                .set_password(Uuid::new_v4(), "whatever")
                .await
                .unwrap(),
            "unknown user id must report false, not error"
        );
    }

    #[tokio::test]
    async fn changing_a_password_revokes_all_existing_sessions() {
        let store = test_store().await;
        let user = store
            .create_user("alice", "old-password", false, false, None)
            .await
            .unwrap();
        let first = store
            .create_session(user.id, chrono::Duration::days(7))
            .await
            .unwrap();
        let second = store
            .create_session(user.id, chrono::Duration::days(7))
            .await
            .unwrap();

        assert!(store.authenticate_session(&first).await.unwrap().is_some());
        assert!(store.authenticate_session(&second).await.unwrap().is_some());
        assert_eq!(store.delete_sessions_for_user(user.id).await.unwrap(), 2);
        assert!(store.authenticate_session(&first).await.unwrap().is_none());
        assert!(store.authenticate_session(&second).await.unwrap().is_none());
    }

    /// Direct user request 2026-08-26: the first-run bootstrap account ships with a
    /// fixed, publicly-known `admin`/`admin` login — `must_change_password` is what makes
    /// that safe (see `discovery-agent::main`'s docs) instead of a standing open door.
    /// This pins the whole lifecycle: created with the flag set, still set after a wrong
    /// password attempt, cleared the moment a real password is set — whether that's a
    /// self-service change or (as here) any other `set_password` caller, since the store
    /// itself can't distinguish the two and shouldn't need to.
    #[tokio::test]
    async fn must_change_password_is_set_on_creation_and_cleared_by_set_password() {
        let store = test_store().await;
        let user = store
            .create_user("admin", "admin", true, true, None)
            .await
            .unwrap();
        assert!(user.must_change_password);

        let verified = store
            .verify_password("admin", "admin")
            .await
            .unwrap()
            .unwrap();
        assert!(
            verified.must_change_password,
            "verify_password must reflect the current flag, not silently drop it"
        );

        assert!(store
            .set_password(user.id, "a-real-password")
            .await
            .unwrap());
        let after = store.get_user_by_id(user.id).await.unwrap().unwrap();
        assert!(
            !after.must_change_password,
            "setting a real password must clear the forced-change flag"
        );
    }

    #[tokio::test]
    async fn delete_user_cascades_sessions_and_unsets_role_membership_is_independent() {
        let store = test_store().await;
        let role = store
            .create_role("ops", HashMap::from([(Domain::Alerts, AccessLevel::Write)]))
            .await
            .unwrap();
        let user = store
            .create_user("alice", "hunter2", false, false, Some(role.id))
            .await
            .unwrap();
        let token = store
            .create_session(user.id, chrono::Duration::hours(1))
            .await
            .unwrap();

        assert!(store.delete_user(user.id).await.unwrap());
        assert!(
            !store.delete_user(user.id).await.unwrap(),
            "deleting an already-gone user must report false, not error"
        );

        assert!(
            store.authenticate_session(&token).await.unwrap().is_none(),
            "session must be gone after cascading delete"
        );
        // The role itself must survive deleting a user who merely had it assigned.
        assert!(store.get_role(role.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn role_missing_means_no_access_admin_bypasses_everything() {
        let store = test_store().await;
        let role = store
            .create_role(
                "read-devices",
                HashMap::from([(Domain::Devices, AccessLevel::Read)]),
            )
            .await
            .unwrap();
        let regular = store
            .create_user("bob", "pw", false, false, Some(role.id))
            .await
            .unwrap();
        let admin = store
            .create_user("root", "pw", true, false, None)
            .await
            .unwrap();

        let token = store
            .create_session(regular.id, chrono::Duration::hours(1))
            .await
            .unwrap();
        let auth_user = store.authenticate_session(&token).await.unwrap().unwrap();

        assert!(auth_user.can(Domain::Devices, AccessLevel::Read));
        assert!(
            !auth_user.can(Domain::Devices, AccessLevel::Write),
            "Read must not satisfy a Write requirement"
        );
        assert!(
            !auth_user.can(Domain::Alerts, AccessLevel::Read),
            "a domain never granted must deny access"
        );

        let admin_token = store
            .create_session(admin.id, chrono::Duration::hours(1))
            .await
            .unwrap();
        let admin_user = store
            .authenticate_session(&admin_token)
            .await
            .unwrap()
            .unwrap();
        assert!(
            admin_user.can(Domain::Alerts, AccessLevel::Write),
            "admin bypasses per-domain permissions entirely, even with no role assigned"
        );
    }

    #[tokio::test]
    async fn user_with_no_role_has_no_access() {
        let store = test_store().await;
        let user = store
            .create_user("alice", "hunter2", false, false, None)
            .await
            .unwrap();
        let token = store
            .create_session(user.id, chrono::Duration::hours(1))
            .await
            .unwrap();
        let auth_user = store.authenticate_session(&token).await.unwrap().unwrap();
        assert!(!auth_user.can(Domain::Devices, AccessLevel::Read));
    }

    #[tokio::test]
    async fn deleting_a_role_unassigns_its_users_instead_of_deleting_them() {
        let store = test_store().await;
        let role = store
            .create_role("ops", HashMap::from([(Domain::Alerts, AccessLevel::Write)]))
            .await
            .unwrap();
        let user = store
            .create_user("alice", "hunter2", false, false, Some(role.id))
            .await
            .unwrap();

        assert!(store.delete_role(role.id).await.unwrap());
        assert!(
            !store.delete_role(role.id).await.unwrap(),
            "deleting an already-gone role must report false, not error"
        );

        let after = store.get_user_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(
            after.role_id, None,
            "the user must survive, unassigned — not cascade-deleted"
        );
    }

    #[tokio::test]
    async fn set_user_role_reassigns_and_clears() {
        let store = test_store().await;
        let role_a = store
            .create_role("a", HashMap::from([(Domain::Jobs, AccessLevel::Read)]))
            .await
            .unwrap();
        let role_b = store
            .create_role("b", HashMap::from([(Domain::Jobs, AccessLevel::Write)]))
            .await
            .unwrap();
        let user = store
            .create_user("alice", "hunter2", false, false, Some(role_a.id))
            .await
            .unwrap();

        assert!(store.set_user_role(user.id, Some(role_b.id)).await.unwrap());
        assert_eq!(
            store
                .get_user_by_id(user.id)
                .await
                .unwrap()
                .unwrap()
                .role_id,
            Some(role_b.id)
        );

        assert!(store.set_user_role(user.id, None).await.unwrap());
        assert_eq!(
            store
                .get_user_by_id(user.id)
                .await
                .unwrap()
                .unwrap()
                .role_id,
            None
        );

        assert!(
            !store.set_user_role(Uuid::new_v4(), None).await.unwrap(),
            "unknown user id must report false, not error"
        );
    }

    #[tokio::test]
    async fn update_role_replaces_the_whole_permission_set_and_can_rename() {
        let store = test_store().await;
        let role = store
            .create_role(
                "ops",
                HashMap::from([
                    (Domain::Jobs, AccessLevel::Read),
                    (Domain::Alerts, AccessLevel::Read),
                ]),
            )
            .await
            .unwrap();

        assert!(store
            .update_role(
                role.id,
                "ops-renamed",
                HashMap::from([(Domain::Jobs, AccessLevel::Write)])
            )
            .await
            .unwrap());
        let after = store.get_role(role.id).await.unwrap().unwrap();
        assert_eq!(after.name, "ops-renamed");
        assert_eq!(
            after.permissions.get(&Domain::Jobs),
            Some(&AccessLevel::Write)
        );
        assert!(
            !after.permissions.contains_key(&Domain::Alerts),
            "a domain left out of the new set must be gone, not merged"
        );

        assert!(
            !store
                .update_role(Uuid::new_v4(), "whatever", HashMap::new())
                .await
                .unwrap(),
            "unknown role id must report false, not error"
        );
    }

    #[tokio::test]
    async fn create_role_rejects_duplicate_name_update_role_rejects_renaming_into_a_collision() {
        let store = test_store().await;
        store.create_role("ops", HashMap::new()).await.unwrap();
        assert!(store
            .create_role("ops", HashMap::new())
            .await
            .unwrap_err()
            .to_string()
            .contains("already taken"));

        let other = store.create_role("support", HashMap::new()).await.unwrap();
        assert!(store
            .update_role(other.id, "ops", HashMap::new())
            .await
            .unwrap_err()
            .to_string()
            .contains("already taken"));
        // Renaming a role to its own current name must not spuriously collide with itself.
        assert!(store
            .update_role(other.id, "support", HashMap::new())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn expired_session_does_not_authenticate_and_is_swept_by_delete_expired() {
        let store = test_store().await;
        let user = store
            .create_user("alice", "hunter2", false, false, None)
            .await
            .unwrap();
        // Negative TTL — already expired the moment it's created.
        let token = store
            .create_session(user.id, chrono::Duration::seconds(-1))
            .await
            .unwrap();

        assert!(store.authenticate_session(&token).await.unwrap().is_none());
        assert_eq!(store.delete_expired_sessions().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn logout_deletes_the_session_and_is_idempotent() {
        let store = test_store().await;
        let user = store
            .create_user("alice", "hunter2", false, false, None)
            .await
            .unwrap();
        let token = store
            .create_session(user.id, chrono::Duration::hours(1))
            .await
            .unwrap();

        assert!(store.authenticate_session(&token).await.unwrap().is_some());
        store.delete_session(&token).await.unwrap();
        assert!(store.authenticate_session(&token).await.unwrap().is_none());
        store.delete_session(&token).await.unwrap(); // must not error on an already-gone session
    }

    #[tokio::test]
    async fn user_count_reflects_creates_and_deletes() {
        let store = test_store().await;
        assert_eq!(store.user_count().await.unwrap(), 0);
        let user = store
            .create_user("alice", "hunter2", false, false, None)
            .await
            .unwrap();
        assert_eq!(store.user_count().await.unwrap(), 1);
        store.delete_user(user.id).await.unwrap();
        assert_eq!(store.user_count().await.unwrap(), 0);
    }
}
