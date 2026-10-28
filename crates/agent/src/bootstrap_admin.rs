//! First-run administrator provisioning.

/// Environment variable used to provision the first administrator when the selected
/// authentication store is empty.  It is intentionally not a default: a deployment must
/// choose the secret before the HTTP listener is started.
pub const BOOTSTRAP_ADMIN_PASSWORD_ENV: &str = "DISCOVERY_BOOTSTRAP_ADMIN_PASSWORD";

/// Reads the one-time bootstrap password without ever putting its value in an error or a
/// log record.  An empty value is rejected as missing so an accidental `VAR=` cannot open
/// a passwordless account.
pub fn bootstrap_admin_password() -> anyhow::Result<String> {
    let password = std::env::var(BOOTSTRAP_ADMIN_PASSWORD_ENV).map_err(|_| {
        anyhow::anyhow!(
            "the first administrator is not provisioned: set {BOOTSTRAP_ADMIN_PASSWORD_ENV} before starting discovery"
        )
    })?;
    if password.is_empty() {
        anyhow::bail!("{BOOTSTRAP_ADMIN_PASSWORD_ENV} must not be empty")
    }
    discovery_auth::validate_password(&password).map_err(|_| {
        anyhow::anyhow!("{BOOTSTRAP_ADMIN_PASSWORD_ENV} must contain at least 8 characters")
    })?;
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_bootstrap_secret_fails_without_disclosing_a_value() {
        let previous = std::env::var_os(BOOTSTRAP_ADMIN_PASSWORD_ENV);
        std::env::remove_var(BOOTSTRAP_ADMIN_PASSWORD_ENV);

        let error = bootstrap_admin_password().unwrap_err().to_string();
        assert!(error.contains(BOOTSTRAP_ADMIN_PASSWORD_ENV));
        assert!(!error.contains("admin/admin"));

        if let Some(value) = previous {
            std::env::set_var(BOOTSTRAP_ADMIN_PASSWORD_ENV, value);
        }
    }

    #[test]
    fn empty_bootstrap_secret_is_rejected() {
        let previous = std::env::var_os(BOOTSTRAP_ADMIN_PASSWORD_ENV);
        std::env::set_var(BOOTSTRAP_ADMIN_PASSWORD_ENV, "");

        assert!(bootstrap_admin_password().is_err());

        match previous {
            Some(value) => std::env::set_var(BOOTSTRAP_ADMIN_PASSWORD_ENV, value),
            None => std::env::remove_var(BOOTSTRAP_ADMIN_PASSWORD_ENV),
        }
    }

    #[test]
    fn short_bootstrap_secret_is_rejected_without_disclosing_it() {
        let previous = std::env::var_os(BOOTSTRAP_ADMIN_PASSWORD_ENV);
        std::env::set_var(BOOTSTRAP_ADMIN_PASSWORD_ENV, "short");

        let error = bootstrap_admin_password().unwrap_err().to_string();
        assert!(error.contains(BOOTSTRAP_ADMIN_PASSWORD_ENV));
        assert!(!error.contains("short"));

        match previous {
            Some(value) => std::env::set_var(BOOTSTRAP_ADMIN_PASSWORD_ENV, value),
            None => std::env::remove_var(BOOTSTRAP_ADMIN_PASSWORD_ENV),
        }
    }
}
