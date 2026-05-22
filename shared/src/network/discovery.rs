use std::time::Duration;
use tokio::time::sleep;

/// Retry intervals for client authentication requests (exponential backoff)
pub fn get_client_retry_interval(attempt: u32) -> Duration {
    let base_ms = 200u64;
    let interval_ms = base_ms * (2u64.pow(attempt.min(5)));
    Duration::from_millis(interval_ms)
}

/// Retry interval for server responses (fixed)
pub fn get_server_retry_interval() -> Duration {
    Duration::from_millis(500)
}

/// Session timeout
pub fn get_session_timeout() -> Duration {
    Duration::from_secs(120)
}

/// Retransmission helper for client
pub async fn retransmit_with_backoff<F, T, E>(
    mut send_fn: F,
    max_duration: Duration,
) -> Result<Option<T>, E>
where
    F: FnMut(u32) -> Result<Option<T>, E>,
{
    let start = std::time::Instant::now();
    let mut attempt = 0u32;

    loop {
        match send_fn(attempt)? {
            Some(result) => return Ok(Some(result)),
            None => {
                if start.elapsed() >= max_duration {
                    break;
                }

                let interval = get_client_retry_interval(attempt);
                sleep(interval).await;
                attempt += 1;
            }
        }
    }

    // Timed out without success
    Ok(None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_intervals() {
        // First retry should be 200ms
        assert_eq!(get_client_retry_interval(0), Duration::from_millis(200));

        // Second retry should be 400ms
        assert_eq!(get_client_retry_interval(1), Duration::from_millis(400));

        // Third retry should be 800ms
        assert_eq!(get_client_retry_interval(2), Duration::from_millis(800));
    }

    #[test]
    fn test_server_retry() {
        assert_eq!(get_server_retry_interval(), Duration::from_millis(500));
    }

    #[test]
    fn test_session_timeout() {
        assert_eq!(get_session_timeout(), Duration::from_secs(120));
    }

    #[test]
    fn test_retry_interval_max_backoff() {
        // After 5 attempts, backoff should cap at 6400ms
        assert_eq!(get_client_retry_interval(5), Duration::from_millis(6400));

        // Further attempts should stay at max
        assert_eq!(get_client_retry_interval(6), Duration::from_millis(6400));
        assert_eq!(get_client_retry_interval(10), Duration::from_millis(6400));
        assert_eq!(get_client_retry_interval(100), Duration::from_millis(6400));
    }

    #[test]
    fn test_retry_interval_exponential_growth() {
        // Verify exponential backoff sequence
        assert_eq!(get_client_retry_interval(0), Duration::from_millis(200)); // 200 * 2^0
        assert_eq!(get_client_retry_interval(1), Duration::from_millis(400)); // 200 * 2^1
        assert_eq!(get_client_retry_interval(2), Duration::from_millis(800)); // 200 * 2^2
        assert_eq!(get_client_retry_interval(3), Duration::from_millis(1600)); // 200 * 2^3
        assert_eq!(get_client_retry_interval(4), Duration::from_millis(3200)); // 200 * 2^4
    }
}
