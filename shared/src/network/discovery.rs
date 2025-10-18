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
) -> Result<T, E>
where
    F: FnMut(u32) -> Result<Option<T>, E>,
{
    let start = std::time::Instant::now();
    let mut attempt = 0u32;

    loop {
        match send_fn(attempt)? {
            Some(result) => return Ok(result),
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

    // Return error after timeout
    // This requires the error type to be constructible
    // In practice, the caller should handle this
    panic!("Retransmission timeout")
}

#[cfg(test)]
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
}
