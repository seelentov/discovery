//! At-rest encryption for SNMPv3 auth/priv passphrases (`discovery_core::SnmpV3AuthCreds`/
//! `SnmpV3PrivCreds`). These are meaningfully more sensitive than a v1/v2c community
//! string — a compromised DB dump shouldn't hand over live USM credentials — so unlike
//! community strings (still plaintext, unchanged), `SnmpAuth::UsmV3` passphrases are
//! encrypted before a store writes its JSON blob to disk, decrypted after reading it back.
//! [`encrypt_auth_secrets`]/[`decrypt_auth_secrets`] live here (not duplicated in
//! `discovery-config-store`/`discovery-devices`, which both need identical logic) because
//! `SnmpAuth` is already defined in this same crate.

use crate::device::{SnmpAuth, SshAuth};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// Env var holding the base64-encoded 32-byte master key. Read once at bootstrap
/// (`discovery-bootstrap`), then threaded into whichever stores need it as
/// `Option<Arc<SecretKey>>` — `None` is fine as long as no `SnmpAuth::UsmV3` ever needs
/// persisting (a deployment with only v1/v2c devices never needs this set).
pub const SECRET_KEY_ENV_VAR: &str = "DISCOVERY_SECRET_KEY";

const NONCE_LEN: usize = 12; // AES-GCM's standard 96-bit nonce.

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("{SECRET_KEY_ENV_VAR} is not set")]
    KeyNotSet,
    #[error("{SECRET_KEY_ENV_VAR} is not valid base64: {0}")]
    KeyNotBase64(base64::DecodeError),
    #[error("{SECRET_KEY_ENV_VAR} must decode to exactly 32 bytes (got {0})")]
    KeyWrongLength(usize),
    #[error("ciphertext is not valid base64: {0}")]
    CiphertextNotBase64(base64::DecodeError),
    #[error("ciphertext is too short to contain a nonce")]
    CiphertextTooShort,
    #[error("decryption failed — wrong key, or corrupted/tampered ciphertext")]
    DecryptionFailed,
    #[error("decrypted bytes were not valid UTF-8: {0}")]
    NotUtf8(std::str::Utf8Error),
    /// Shared by [`encrypt_auth_secrets`] (SNMPv3 USM passphrases) and
    /// [`encrypt_ssh_auth_secrets`]/[`decrypt_ssh_auth_secrets`] (SSH passwords/private
    /// keys, added 2026-09-07) — deliberately generic wording rather than naming one
    /// credential kind, since this fires for either.
    #[error("these credentials require {SECRET_KEY_ENV_VAR} to be configured")]
    KeyRequired,
}

/// A 256-bit AES-GCM key. Never serialized, never logged (no `Debug`/`Display` on
/// purpose) — lives only in memory for the process's lifetime.
pub struct SecretKey(Aes256Gcm);

impl SecretKey {
    /// Reads and decodes [`SECRET_KEY_ENV_VAR`]. The only way this type gets constructed —
    /// there's no "generate one and keep it in memory" path, because a key nobody else can
    /// reproduce on the next restart would make every already-encrypted passphrase in the
    /// DB permanently unreadable.
    pub fn from_env() -> Result<Self, SecretError> {
        let raw = std::env::var(SECRET_KEY_ENV_VAR).map_err(|_| SecretError::KeyNotSet)?;
        Self::from_base64(raw.trim())
    }

    /// Constructs a key directly from a base64-encoded 32-byte value, bypassing the env
    /// var — the building block [`Self::from_env`] is written on top of, exposed
    /// separately for tests/tools that need a known key without setting process-global
    /// env state (`std::env::set_var` mutating a shared process is exactly the kind of
    /// thing that makes parallel tests flaky).
    pub fn from_base64(encoded: &str) -> Result<Self, SecretError> {
        let bytes = STANDARD
            .decode(encoded)
            .map_err(SecretError::KeyNotBase64)?;
        if bytes.len() != 32 {
            return Err(SecretError::KeyWrongLength(bytes.len()));
        }
        Ok(Self(
            Aes256Gcm::new_from_slice(&bytes).expect("checked exactly 32 bytes above"),
        ))
    }
}

/// Encrypts `plaintext` under `key`. Output is `base64(nonce || ciphertext)` — a single
/// opaque string, safe to drop straight into a JSON field in place of the plaintext it
/// replaces. A fresh random nonce every call (never reused per key, as AES-GCM requires).
pub fn encrypt_secret(key: &SecretKey, plaintext: &str) -> String {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = key
        .0
        .encrypt(&nonce, plaintext.as_bytes())
        .expect("AES-GCM encryption of a short passphrase does not fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    STANDARD.encode(out)
}

/// Reverses [`encrypt_secret`]. Fails on a wrong key, a corrupted/truncated blob, or
/// (extremely unlikely) valid-decryption-but-non-UTF8 bytes — GCM's authentication tag
/// means "wrong key" and "tampered ciphertext" are indistinguishable by design, so both
/// surface as [`SecretError::DecryptionFailed`].
pub fn decrypt_secret(key: &SecretKey, ciphertext: &str) -> Result<String, SecretError> {
    let raw = STANDARD
        .decode(ciphertext)
        .map_err(SecretError::CiphertextNotBase64)?;
    if raw.len() < NONCE_LEN {
        return Err(SecretError::CiphertextTooShort);
    }
    let (nonce_bytes, ct) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = key
        .0
        .decrypt(nonce, ct)
        .map_err(|_| SecretError::DecryptionFailed)?;
    String::from_utf8(plaintext).map_err(|e| SecretError::NotUtf8(e.utf8_error()))
}

/// Encrypts the auth/priv passphrases inside `auth` in place, if it's `UsmV3` — a no-op
/// (`Ok` unchanged) for `Community`, which has no secret worth protecting. Called by a
/// store right before serializing an `SnmpAuth` into the JSON blob it writes to disk.
///
/// Fails with [`SecretError::KeyRequired`] if `key` is `None` and `auth` actually has a
/// passphrase to encrypt — a deployment that never uses v3 never needs a key configured,
/// but one that does must not silently fall back to writing plaintext.
pub fn encrypt_auth_secrets(
    auth: SnmpAuth,
    key: Option<&SecretKey>,
) -> Result<SnmpAuth, SecretError> {
    let SnmpAuth::UsmV3(mut creds) = auth else {
        return Ok(auth);
    };
    let key = key.ok_or(SecretError::KeyRequired)?;
    if let Some(a) = &mut creds.auth {
        a.passphrase = encrypt_secret(key, &a.passphrase);
    }
    if let Some(p) = &mut creds.priv_ {
        p.passphrase = encrypt_secret(key, &p.passphrase);
    }
    Ok(SnmpAuth::UsmV3(creds))
}

/// Reverses [`encrypt_auth_secrets`] — called by a store right after deserializing an
/// `SnmpAuth` read back from a JSON blob. Same `KeyRequired` failure mode: a `UsmV3` row
/// existing in the DB with no key configured to decrypt it is a misconfiguration, not
/// something to paper over by returning the ciphertext as if it were the real passphrase.
pub fn decrypt_auth_secrets(
    auth: SnmpAuth,
    key: Option<&SecretKey>,
) -> Result<SnmpAuth, SecretError> {
    let SnmpAuth::UsmV3(mut creds) = auth else {
        return Ok(auth);
    };
    let key = key.ok_or(SecretError::KeyRequired)?;
    if let Some(a) = &mut creds.auth {
        a.passphrase = decrypt_secret(key, &a.passphrase)?;
    }
    if let Some(p) = &mut creds.priv_ {
        p.passphrase = decrypt_secret(key, &p.passphrase)?;
    }
    Ok(SnmpAuth::UsmV3(creds))
}

/// Encrypts the secret(s) inside an [`SshAuth`] in place — the SSH counterpart of
/// [`encrypt_auth_secrets`]. **Always requires `key`, unlike `SnmpAuth::Community`'s
/// passthrough case** — see [`SshAuth`]'s own docs for why there is no "not really a
/// secret" branch for SSH credentials the way a community string gets. `Password`
/// encrypts the password; `PrivateKey` encrypts the key body and, if present, its
/// passphrase.
pub fn encrypt_ssh_auth_secrets(
    auth: SshAuth,
    key: Option<&SecretKey>,
) -> Result<SshAuth, SecretError> {
    let key = key.ok_or(SecretError::KeyRequired)?;
    Ok(match auth {
        SshAuth::Password { password } => SshAuth::Password {
            password: encrypt_secret(key, &password),
        },
        SshAuth::PrivateKey {
            private_key,
            passphrase,
        } => SshAuth::PrivateKey {
            private_key: encrypt_secret(key, &private_key),
            passphrase: passphrase.map(|p| encrypt_secret(key, &p)),
        },
    })
}

/// Reverses [`encrypt_ssh_auth_secrets`] — called right after reading an [`SshAuth`] blob
/// back out of storage. Same `KeyRequired` failure mode as [`decrypt_auth_secrets`]: an
/// `ssh_auth` row existing with no key configured to decrypt it is a misconfiguration, not
/// something to paper over by returning ciphertext as if it were the real credential.
pub fn decrypt_ssh_auth_secrets(
    auth: SshAuth,
    key: Option<&SecretKey>,
) -> Result<SshAuth, SecretError> {
    let key = key.ok_or(SecretError::KeyRequired)?;
    Ok(match auth {
        SshAuth::Password { password } => SshAuth::Password {
            password: decrypt_secret(key, &password)?,
        },
        SshAuth::PrivateKey {
            private_key,
            passphrase,
        } => SshAuth::PrivateKey {
            private_key: decrypt_secret(key, &private_key)?,
            passphrase: passphrase.map(|p| decrypt_secret(key, &p)).transpose()?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{SnmpAuthProtocol, SnmpPrivProtocol};
    use crate::device::{SnmpV3AuthCreds, SnmpV3Credentials, SnmpV3PrivCreds};

    fn v3_auth() -> SnmpAuth {
        SnmpAuth::UsmV3(SnmpV3Credentials {
            user: "monitor".to_string(),
            auth: Some(SnmpV3AuthCreds {
                protocol: SnmpAuthProtocol::Sha1,
                passphrase: "authpass123".to_string(),
            }),
            priv_: Some(SnmpV3PrivCreds {
                protocol: SnmpPrivProtocol::Aes128,
                passphrase: "privpass123".to_string(),
            }),
        })
    }

    #[test]
    fn community_auth_passes_through_encrypt_and_decrypt_unchanged_without_a_key() {
        let auth = SnmpAuth::Community {
            version: crate::device::SnmpVersion::V2c,
            community: "public".to_string(),
        };
        assert_eq!(encrypt_auth_secrets(auth.clone(), None).unwrap(), auth);
        assert_eq!(decrypt_auth_secrets(auth.clone(), None).unwrap(), auth);
    }

    #[test]
    fn usm_v3_without_a_key_fails_instead_of_writing_plaintext() {
        assert!(matches!(
            encrypt_auth_secrets(v3_auth(), None),
            Err(SecretError::KeyRequired)
        ));
    }

    #[test]
    fn usm_v3_round_trips_through_encrypt_then_decrypt_with_the_same_key() {
        let key = SecretKey::from_base64(&STANDARD.encode([7u8; 32])).unwrap();
        let original = v3_auth();
        let encrypted = encrypt_auth_secrets(original.clone(), Some(&key)).unwrap();
        // Ciphertext, not the original passphrase, must actually be on the wire form.
        let SnmpAuth::UsmV3(ref enc_creds) = encrypted else {
            unreachable!()
        };
        assert_ne!(enc_creds.auth.as_ref().unwrap().passphrase, "authpass123");
        assert_ne!(enc_creds.priv_.as_ref().unwrap().passphrase, "privpass123");

        let decrypted = decrypt_auth_secrets(encrypted, Some(&key)).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn ssh_password_without_a_key_fails_instead_of_writing_plaintext() {
        let auth = SshAuth::Password {
            password: "hunter2".to_string(),
        };
        assert!(
            matches!(
                encrypt_ssh_auth_secrets(auth, None),
                Err(SecretError::KeyRequired)
            ),
            "unlike SnmpAuth::Community, SSH has no plaintext-ok branch"
        );
    }

    #[test]
    fn ssh_password_round_trips_through_encrypt_then_decrypt_with_the_same_key() {
        let key = SecretKey::from_base64(&STANDARD.encode([9u8; 32])).unwrap();
        let original = SshAuth::Password {
            password: "hunter2".to_string(),
        };
        let encrypted = encrypt_ssh_auth_secrets(original.clone(), Some(&key)).unwrap();
        let SshAuth::Password { ref password } = encrypted else {
            unreachable!()
        };
        assert_ne!(
            password, "hunter2",
            "the ciphertext, not the plaintext password, must be what's on the wire form"
        );

        let decrypted = decrypt_ssh_auth_secrets(encrypted, Some(&key)).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn ssh_private_key_with_passphrase_round_trips_through_encrypt_then_decrypt() {
        let key = SecretKey::from_base64(&STANDARD.encode([9u8; 32])).unwrap();
        let original = SshAuth::PrivateKey {
            private_key: "-----BEGIN KEY-----\nabc\n-----END KEY-----".to_string(),
            passphrase: Some("keypass".to_string()),
        };
        let encrypted = encrypt_ssh_auth_secrets(original.clone(), Some(&key)).unwrap();
        let SshAuth::PrivateKey {
            ref private_key,
            ref passphrase,
        } = encrypted
        else {
            unreachable!()
        };
        assert_ne!(private_key, "-----BEGIN KEY-----\nabc\n-----END KEY-----");
        assert_ne!(passphrase.as_deref(), Some("keypass"));

        let decrypted = decrypt_ssh_auth_secrets(encrypted, Some(&key)).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn ssh_private_key_without_passphrase_round_trips_through_encrypt_then_decrypt() {
        let key = SecretKey::from_base64(&STANDARD.encode([9u8; 32])).unwrap();
        let original = SshAuth::PrivateKey {
            private_key: "-----BEGIN KEY-----\nabc\n-----END KEY-----".to_string(),
            passphrase: None,
        };
        let encrypted = encrypt_ssh_auth_secrets(original.clone(), Some(&key)).unwrap();
        let decrypted = decrypt_ssh_auth_secrets(encrypted, Some(&key)).unwrap();
        assert_eq!(decrypted, original);
    }

    fn test_key() -> SecretKey {
        // 32 zero bytes, base64-encoded — fine for tests, never used outside them.
        SecretKey::from_base64(&STANDARD.encode([0u8; 32])).unwrap()
    }

    #[test]
    fn round_trips_plaintext_through_encrypt_then_decrypt() {
        let key = test_key();
        let ciphertext = encrypt_secret(&key, "authpass123");
        assert_eq!(decrypt_secret(&key, &ciphertext).unwrap(), "authpass123");
    }

    #[test]
    fn two_encryptions_of_the_same_plaintext_differ_because_the_nonce_is_random() {
        let key = test_key();
        let a = encrypt_secret(&key, "same passphrase");
        let b = encrypt_secret(&key, "same passphrase");
        assert_ne!(
            a, b,
            "reusing a nonce under the same key would break AES-GCM's guarantees"
        );
    }

    #[test]
    fn decrypting_with_the_wrong_key_fails_instead_of_returning_garbage() {
        let key_a = test_key();
        let key_b = SecretKey::from_base64(&STANDARD.encode([1u8; 32])).unwrap();
        let ciphertext = encrypt_secret(&key_a, "secret");
        assert!(matches!(
            decrypt_secret(&key_b, &ciphertext),
            Err(SecretError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypting_corrupted_ciphertext_fails_cleanly() {
        let key = test_key();
        let ciphertext = encrypt_secret(&key, "secret");
        // Corrupt the *decoded* bytes (not the base64 text directly) so the result is
        // still syntactically valid base64 — the point is a broken GCM auth tag, not a
        // base64-decode error, which `CiphertextNotBase64`/`CiphertextTooShort` already
        // cover separately.
        let mut raw = STANDARD.decode(&ciphertext).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        let corrupted = STANDARD.encode(raw);
        assert!(matches!(
            decrypt_secret(&key, &corrupted),
            Err(SecretError::DecryptionFailed)
        ));
    }

    #[test]
    fn key_from_base64_rejects_wrong_length() {
        let short = STANDARD.encode([0u8; 16]);
        assert!(matches!(
            SecretKey::from_base64(&short),
            Err(SecretError::KeyWrongLength(16))
        ));
    }

    #[test]
    fn from_env_fails_clearly_when_the_env_var_is_unset() {
        // SAFETY-adjacent note, not the memory kind: `remove_var`/`set_var` mutate
        // process-global state, so if this crate's tests ever run these in parallel
        // against the same var they'd race. `SECRET_KEY_ENV_VAR` isn't touched by any
        // other test in this module (see `test_key`'s direct `from_base64` construction,
        // used everywhere else specifically to avoid touching env at all).
        std::env::remove_var(SECRET_KEY_ENV_VAR);
        assert!(matches!(SecretKey::from_env(), Err(SecretError::KeyNotSet)));
    }
}
