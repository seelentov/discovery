//! `discovery-auth` — local username/password authentication + classic per-domain
//! read/write permissions (2026-08-21, direct user request: "логика авторизации и
//! аутентификации. Как и rest, так и для webui... permissions. Классический вид доступа -
//! чтение, запись, для различных доменов"). External providers (LDAP/Kerberos/OAuth/
//! Tibbo cloud — see `discovery/CLAUDE.md`'s AggreGate auth survey) are explicitly
//! deferred pending discussion; this crate only implements local password auth, but
//! [`AuthStore::verify_password`]/[`AuthStore::create_session`] are already split apart
//! (checking credentials vs. issuing a session) specifically so an external provider could
//! later slot in as an alternative to `verify_password` without touching sessions or
//! permissions at all — same "one authentication outcome, one internal user" shape
//! AggreGate's own plugin family uses.

mod model;
mod password;
mod sea_orm_store;
mod store;
mod token;

pub use model::*;
pub use password::*;
pub use sea_orm_store::SeaOrmAuthStore;
pub use store::AuthStore;
pub use token::*;
