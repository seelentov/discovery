use rand::RngCore;
use sha2::{Digest, Sha256};

/// A fresh 256-bit random session token, hex-encoded — this is the value handed to the
/// client (cookie/`Authorization: Bearer`), never stored anywhere as-is. See
/// [`hash_token`]'s docs for what actually lands in the `sessions` table.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// What the `sessions` table actually stores as its primary key
/// (`discovery_migration`'s `up()` docs) — SHA-256 of the raw token, not the token itself,
/// so a database read can't be turned directly into a valid session.
pub fn hash_token(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_hash_deterministically() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert_eq!(
            hash_token(&a),
            hash_token(&a),
            "hashing the same token twice must be deterministic"
        );
        assert_ne!(hash_token(&a), hash_token(&b));
    }
}
