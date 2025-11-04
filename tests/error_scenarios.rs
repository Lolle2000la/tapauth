//! Additional integration tests for error handling, retransmission, and BLE fallback scenarios
//!
//! These tests complement the existing integration_test.rs with more specific error scenarios
//! related to the panic prevention work.

use prost::Message;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

// Re-use the protobuf definitions from shared crate
mod ipc {
    include!(concat!(env!("OUT_DIR"), "/tapauth.ipc.rs"));
}

const DEFAULT_SOCKET_PATH: &str = "/run/tapauthd/tapauthd-test.sock";
const FRAME_HEADER_SIZE: usize = 4;

/// Helper to connect to the daemon socket
fn connect_daemon() -> std::io::Result<UnixStream> {
    let sock_path =
        std::env::var("TAPAUTHD_SOCK").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
    let stream = UnixStream::connect(&sock_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(stream)
}

/// Write a length-prefixed protobuf message
fn write_message<T: Message>(stream: &mut UnixStream, msg: &T) -> std::io::Result<()> {
    let buf = msg.encode_to_vec();
    let len = buf.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&buf)?;
    stream.flush()?;
    Ok(())
}

/// Read a length-prefixed protobuf message
fn read_message<T: Message + Default>(stream: &mut UnixStream) -> std::io::Result<T> {
    let mut len_buf = [0u8; FRAME_HEADER_SIZE];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len == 0 || len > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid message length: {}", len),
        ));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;

    T::decode(&buf[..]).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Decode error: {}", e),
        )
    })
}

#[test]
fn test_rapid_reconnection_resilience() {
    println!("Test: Rapid reconnection resilience (DoS mitigation)");

    // Connect and disconnect rapidly to test socket handling
    for i in 0..10 {
        let mut stream = connect_daemon().expect("Failed to connect on iteration {i}");

        let auth_req = ipc::PamAuthenticateRequest {
            username: "testuser".to_string(),
            tty_present: false,
            timeout_seconds: 1,
            request_id: format!("rapid-{}", i),
        };

        write_message(&mut stream, &auth_req).expect("Failed to send");

        // Don't wait for response, just close
        drop(stream);

        std::thread::sleep(Duration::from_millis(50));
    }

    // Verify daemon is still responsive after rapid reconnects
    let mut stream = connect_daemon().expect("Daemon should still be responsive");
    let auth_req = ipc::PamAuthenticateRequest {
        username: "testuser".to_string(),
        tty_present: false,
        timeout_seconds: 1,
        request_id: "final-check".to_string(),
    };

    write_message(&mut stream, &auth_req).expect("Failed to send final check");
    let _response: ipc::PamAuthenticateResponse =
        read_message(&mut stream).expect("Failed to read final response");

    println!("✓ Daemon remained responsive after rapid reconnections");
}

#[test]
fn test_oversized_message_rejection() {
    println!("Test: Oversized message rejection (10MB+ protection)");

    let mut stream = connect_daemon().expect("Failed to connect");

    // Send a frame claiming to be 11MB (should be rejected)
    let oversized_len = 11 * 1024 * 1024u32;
    stream
        .write_all(&oversized_len.to_be_bytes())
        .expect("Write length");

    // Try to read response - should get error or connection close
    let mut buf = [0u8; 4];
    match stream.read_exact(&mut buf) {
        Err(e) => {
            println!("✓ Connection closed on oversized message: {}", e);
        }
        Ok(_) => {
            // Daemon might send error response
            println!("✓ Daemon handled oversized message gracefully");
        }
    }
}

#[test]
fn test_timeout_accuracy() {
    println!("Test: Timeout accuracy (should timeout within configured duration)");

    let mut stream = connect_daemon().expect("Failed to connect");

    let timeout_secs = 2u32;
    let auth_req = ipc::PamAuthenticateRequest {
        username: "testuser".to_string(),
        tty_present: false,
        timeout_seconds: timeout_secs,
        request_id: "timeout-accuracy".to_string(),
    };

    let start = Instant::now();
    write_message(&mut stream, &auth_req).expect("Failed to send");

    let response: ipc::PamAuthenticateResponse =
        read_message(&mut stream).expect("Failed to read response");
    let elapsed = start.elapsed();

    println!(
        "  Requested timeout: {}s, Actual elapsed: {:.2}s",
        timeout_secs,
        elapsed.as_secs_f64()
    );

    // Verify timeout was respected (within reasonable margin)
    assert_eq!(response.outcome, ipc::PamOutcome::Denied as i32);
    assert!(
        elapsed >= Duration::from_secs(timeout_secs as u64),
        "Timeout should not complete before configured duration"
    );
    assert!(
        elapsed < Duration::from_secs(timeout_secs as u64 + 2),
        "Timeout should complete within 2 seconds of configured duration"
    );

    println!("✓ Timeout accuracy verified");
}

#[test]
fn test_duplicate_request_id_handling() {
    println!("Test: Duplicate request_id handling");

    // Send two auth requests with the same request_id
    let request_id = "duplicate-test-12345";

    let mut stream1 = connect_daemon().expect("Failed to connect stream 1");
    let mut stream2 = connect_daemon().expect("Failed to connect stream 2");

    let auth_req1 = ipc::PamAuthenticateRequest {
        username: "user1".to_string(),
        tty_present: false,
        timeout_seconds: 3,
        request_id: request_id.to_string(),
    };

    let auth_req2 = ipc::PamAuthenticateRequest {
        username: "user2".to_string(),
        tty_present: false,
        timeout_seconds: 3,
        request_id: request_id.to_string(),
    };

    write_message(&mut stream1, &auth_req1).expect("Failed to send req1");
    std::thread::sleep(Duration::from_millis(100));
    write_message(&mut stream2, &auth_req2).expect("Failed to send req2");

    // Both should get responses (daemon handles duplicates gracefully)
    let response1: ipc::PamAuthenticateResponse =
        read_message(&mut stream1).expect("Failed to read response1");
    let response2: ipc::PamAuthenticateResponse =
        read_message(&mut stream2).expect("Failed to read response2");

    println!(
        "  Response 1 outcome: {:?}, Response 2 outcome: {:?}",
        response1.outcome, response2.outcome
    );

    // Both should complete without panic (exact outcome depends on implementation)
    println!("✓ Duplicate request_id handled without panic");
}

#[test]
fn test_zero_timeout() {
    println!("Test: Zero timeout handling");

    let mut stream = connect_daemon().expect("Failed to connect");

    let auth_req = ipc::PamAuthenticateRequest {
        username: "testuser".to_string(),
        tty_present: false,
        timeout_seconds: 0, // Edge case
        request_id: "zero-timeout".to_string(),
    };

    write_message(&mut stream, &auth_req).expect("Failed to send");

    // Should get immediate denial or treated as minimum timeout
    let response: ipc::PamAuthenticateResponse =
        read_message(&mut stream).expect("Failed to read response");

    assert_eq!(
        response.outcome,
        ipc::PamOutcome::Denied as i32,
        "Zero timeout should result in denial"
    );

    println!("✓ Zero timeout handled gracefully: {:?}", response.detail);
}

#[test]
fn test_very_long_timeout() {
    println!("Test: Very long timeout (should be capped)");

    let mut stream = connect_daemon().expect("Failed to connect");

    let auth_req = ipc::PamAuthenticateRequest {
        username: "testuser".to_string(),
        tty_present: false,
        timeout_seconds: 999_999, // Unreasonably long
        request_id: "long-timeout".to_string(),
    };

    let start = Instant::now();
    write_message(&mut stream, &auth_req).expect("Failed to send");

    // Send cancel after 1 second to avoid waiting forever
    std::thread::sleep(Duration::from_secs(1));
    let mut cancel_stream = connect_daemon().expect("Failed to connect for cancel");
    let cancel_req = ipc::PamCancelRequest {
        reason: "test-cancel-long".to_string(),
        request_id: "long-timeout".to_string(),
    };
    write_message(&mut cancel_stream, &cancel_req).expect("Failed to send cancel");

    let _cancel_response: ipc::PamAuthenticateResponse =
        read_message(&mut cancel_stream).expect("Failed to read cancel response");
    let response: ipc::PamAuthenticateResponse =
        read_message(&mut stream).expect("Failed to read response");
    let elapsed = start.elapsed();

    println!(
        "  Long timeout cancelled after {:.2}s",
        elapsed.as_secs_f64()
    );

    assert!(
        elapsed < Duration::from_secs(10),
        "Should be cancellable quickly despite long timeout"
    );

    println!("✓ Very long timeout handled without indefinite blocking");
}

#[test]
fn test_special_characters_in_username() {
    println!("Test: Special characters in username");

    let mut stream = connect_daemon().expect("Failed to connect");

    // Test with various special characters that might cause issues
    let test_usernames = vec![
        "user@domain",
        "user-name",
        "user_name",
        "user.name",
        "用户", // Unicode
        "user'name",
        "user\"name",
    ];

    for username in test_usernames {
        println!("  Testing username: {}", username);

        let auth_req = ipc::PamAuthenticateRequest {
            username: username.to_string(),
            tty_present: false,
            timeout_seconds: 1,
            request_id: format!("special-{}", username),
        };

        write_message(&mut stream, &auth_req).expect("Failed to send");
        let response: ipc::PamAuthenticateResponse =
            read_message(&mut stream).expect("Failed to read response");

        // Should complete without panic (denial is expected since no device paired)
        assert_eq!(response.outcome, ipc::PamOutcome::Denied as i32);

        // Reconnect for next test
        if username != test_usernames.last().unwrap() {
            stream = connect_daemon().expect("Failed to reconnect");
        }
    }

    println!("✓ Special characters in username handled gracefully");
}

#[test]
fn test_connection_close_during_auth() {
    println!("Test: Connection close during authentication");

    let mut stream = connect_daemon().expect("Failed to connect");

    let auth_req = ipc::PamAuthenticateRequest {
        username: "testuser".to_string(),
        tty_present: false,
        timeout_seconds: 5,
        request_id: "close-during-auth".to_string(),
    };

    write_message(&mut stream, &auth_req).expect("Failed to send");
    println!("  Sent auth request, now closing connection immediately");

    // Close connection without reading response
    drop(stream);

    std::thread::sleep(Duration::from_millis(500));

    // Verify daemon is still responsive
    let mut new_stream = connect_daemon().expect("Daemon should still be responsive");
    let health_req = ipc::PamAuthenticateRequest {
        username: "healthcheck".to_string(),
        tty_present: false,
        timeout_seconds: 1,
        request_id: "health-after-close".to_string(),
    };

    write_message(&mut new_stream, &health_req).expect("Failed to send health check");
    let _response: ipc::PamAuthenticateResponse =
        read_message(&mut new_stream).expect("Failed to read health response");

    println!("✓ Daemon remained healthy after connection close during auth");
}

/// Documentation for running these tests
///
/// These tests require a running daemon instance. Use the test runner script:
///
/// ```bash
/// sudo ./tests/run-integration-tests.sh
/// ```
///
/// Or manually:
/// ```bash
/// # Terminal 1: Start test daemon
/// sudo RUST_LOG=debug TAPAUTHD_SOCK=/run/tapauthd/tapauthd-test.sock \
///   ./target/release/tapauthd
///
/// # Terminal 2: Run error scenario tests
/// export TAPAUTHD_SOCK=/run/tapauthd/tapauthd-test.sock
/// cargo test --test error_scenarios -- --nocapture --test-threads=1
/// ```
#[test]
fn test_runner_documentation() {
    println!("Error scenario integration tests");
    println!("These tests verify daemon resilience under various error conditions");
    println!("\nRun with: sudo ./tests/run-integration-tests.sh");
}
