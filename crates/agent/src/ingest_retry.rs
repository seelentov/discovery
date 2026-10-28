use anyhow::Result;
use std::future::Future;
use std::time::Duration;
use tracing::warn;

pub(crate) const SQLITE_BUSY_MAX_ATTEMPTS: usize = 5;
const SQLITE_BUSY_BACKOFF: [Duration; 4] = [
    Duration::from_millis(25),
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(200),
];

pub(crate) fn is_sqlite_busy(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let text = cause.to_string().to_ascii_lowercase();
        text.contains("sqlite_busy")
            || text.contains("database is locked")
            || text.contains("database table is locked")
    })
}

pub(crate) async fn retry_sqlite_busy<T, F, Fut>(
    operation: &'static str,
    mut action: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    for attempt in 1..=SQLITE_BUSY_MAX_ATTEMPTS {
        match action().await {
            Ok(value) => return Ok(value),
            Err(error) if is_sqlite_busy(&error) && attempt < SQLITE_BUSY_MAX_ATTEMPTS => {
                let delay = SQLITE_BUSY_BACKOFF[attempt - 1];
                warn!(
                    operation,
                    attempt,
                    max_attempts = SQLITE_BUSY_MAX_ATTEMPTS,
                    delay_ms = delay.as_millis(),
                    "SQLite busy; retrying ingest operation"
                );
                tokio::time::sleep(delay).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("retry loop always returns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn recognizes_sqlite_busy_variants() {
        assert!(is_sqlite_busy(&anyhow::anyhow!("database is locked")));
        assert!(is_sqlite_busy(&anyhow::anyhow!(
            "SQLITE_BUSY: another writer"
        )));
        assert!(!is_sqlite_busy(&anyhow::anyhow!("connection refused")));
    }

    #[tokio::test]
    async fn retries_then_succeeds_with_bounded_backoff() {
        let attempts = Arc::new(Mutex::new(0));
        let observed = attempts.clone();
        let result = retry_sqlite_busy("test", move || {
            let observed = observed.clone();
            async move {
                let mut count = observed.lock().unwrap();
                *count += 1;
                if *count < 3 {
                    Err(anyhow::anyhow!("database is locked"))
                } else {
                    Ok(42)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(result, 42);
        assert_eq!(*attempts.lock().unwrap(), 3);
    }
}
