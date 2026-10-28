use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Account-management boundaries must validate new passwords before hashing them.
pub fn validate_password(password: &str) -> anyhow::Result<()> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        anyhow::bail!("password must contain at least {MIN_PASSWORD_LENGTH} characters");
    }
    Ok(())
}

/// Argon2id with library defaults (19 MiB memory, 2 iterations, 1 lane — the
/// `argon2` crate's own recommended baseline, not hand-tuned) — no reason to deviate for a
/// single-server dashboard tool with a handful of accounts, and picking custom cost
/// parameters without load-testing them is how you end up with either a login that takes
/// seconds or a hash that's too cheap to matter.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))?;
    Ok(hash.to_string())
}

/// `false` for both "wrong password" and "hash in the database is corrupt/unparseable" —
/// a caller (`AuthStore::verify_password`) never needs to tell those apart, and treating a
/// bad stored hash as "authentication error" would be worse than treating it as "login
/// failed" (fails safe, not open).
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_round_trips() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn same_password_hashes_differently_each_time() {
        // Salted — two hashes of the same password must not be byte-identical, otherwise
        // equal passwords would be equal-hash-distinguishable in a leaked DB dump.
        let a = hash_password("same password").unwrap();
        let b = hash_password("same password").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("same password", &a));
        assert!(verify_password("same password", &b));
    }

    #[test]
    fn corrupt_stored_hash_fails_closed() {
        assert!(!verify_password("anything", "not a real hash"));
    }

    #[test]
    fn password_policy_rejects_empty_and_short_values() {
        assert!(validate_password("").is_err());
        assert!(validate_password("1234567").is_err());
        assert!(validate_password("12345678").is_ok());
    }
}
