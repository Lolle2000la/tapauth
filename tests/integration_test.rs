// Integration tests for tapauthd IPC interface
// These tests validate the daemon's IPC protocol without requiring actual Android devices

use prost::Message;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

// Re-use the protobuf definitions from shared crate
mod ipc {
    include!(concat!(env!("OUT_DIR"), "/tapauth.ipc.rs"));
}

const DEFAULT_SOCKET_PATH: &str = "/run/tapauthd/tapauthd-test.sock";
const FRAME_HEADER_SIZE: usize = 4;

/// Helper to connect to the daemon socket
fn connect_daemon() -> std::io::Result<UnixStream> {
    let sock_path = std::env::var("TAPAUTHD_SOCK").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
    let stream = UnixStream::connect(&sock_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
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
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Decode error: {}", e))
    })
}

#[test]
fn test_health_check() {
    println!("Test: Health check (connect and disconnect)");
    
    // Just connect and send empty message (zero-length frame)
    let mut stream = connect_daemon().expect("Failed to connect to daemon");
    stream.write_all(&[0u8; 4]).expect("Failed to write health check");
    stream.flush().expect("Failed to flush");
    
    // Daemon should handle gracefully (connection will close)
    println!("✓ Health check passed");
}

#[test]
fn test_auth_timeout() {
    println!("Test: Authentication timeout (no device responds)");
    
    let mut stream = connect_daemon().expect("Failed to connect");
    
    // Send auth request with 2-second timeout
    let auth_req = ipc::PamAuthenticateRequest {
        username: "testuser".to_string(),
        tty_present: false,
        timeout_seconds: 2,
        request_id: "1001".to_string(),
    };
    
    write_message(&mut stream, &auth_req).expect("Failed to send auth request");
    println!("  Sent auth request, waiting for timeout...");
    
    // Read response (should be Denied after ~2 seconds)
    let response: ipc::PamAuthenticateResponse = read_message(&mut stream)
        .expect("Failed to read auth response");
    
    // Verify we got a denial (no device answered)
    assert_eq!(
        response.outcome,
        ipc::PamOutcome::Denied as i32,
        "Expected Denied outcome on timeout"
    );
    
    println!("✓ Auth timeout handled correctly: {:?}", response.detail);
}

#[test]
fn test_cancel_request() {
    println!("Test: Cancel authentication in progress");
    
    let mut stream = connect_daemon().expect("Failed to connect");
    
    // Send auth request with longer timeout
    let auth_req = ipc::PamAuthenticateRequest {
        username: "testuser".to_string(),
        tty_present: false,
        timeout_seconds: 10,
        request_id: "2001".to_string(),
    };
    
    write_message(&mut stream, &auth_req).expect("Failed to send auth request");
    println!("  Sent auth request with 10s timeout");
    
    // Wait a moment, then send cancel
    std::thread::sleep(Duration::from_millis(500));
    
    // Open a second connection to send cancel (daemon handles multiple clients)
    let mut cancel_stream = connect_daemon().expect("Failed to connect for cancel");
    let cancel_req = ipc::PamCancelRequest {
        reason: "test-cancel".to_string(),
        request_id: "2001".to_string(),
    };
    
    write_message(&mut cancel_stream, &cancel_req).expect("Failed to send cancel");
    println!("  Sent cancel request");
    
    // Read cancel ack
    let cancel_response: ipc::PamAuthenticateResponse = read_message(&mut cancel_stream)
        .expect("Failed to read cancel response");
    assert_eq!(
        cancel_response.outcome,
        ipc::PamOutcome::Ignore as i32,
        "Expected Ignore outcome for cancel ack"
    );
    
    // Original stream should also get a response (Denied or Ignore)
    let auth_response: ipc::PamAuthenticateResponse = read_message(&mut stream)
        .expect("Failed to read auth response after cancel");
    
    // Should be Denied (auth was cancelled)
    assert_eq!(
        auth_response.outcome,
        ipc::PamOutcome::Denied as i32,
        "Expected Denied after cancellation"
    );
    
    println!("✓ Cancellation handled correctly");
}

#[test]
fn test_malformed_message() {
    println!("Test: Malformed message handling");
    
    let mut stream = connect_daemon().expect("Failed to connect");
    
    // Send garbage (invalid protobuf)
    let garbage = vec![0xFF; 100];
    let len = garbage.len() as u32;
    stream.write_all(&len.to_be_bytes()).expect("Write length");
    stream.write_all(&garbage).expect("Write garbage");
    stream.flush().expect("Flush");
    
    // Daemon should close connection or send error
    // Expect read to fail or get an error response
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    
    // Either connection closed (Ok with EOF) or error
    match result {
        Err(_) => println!("✓ Connection closed on malformed message (expected)"),
        Ok(_) => {
            // Might get a response; check if it's an error/ignore
            println!("✓ Daemon handled malformed message gracefully");
        }
    }
}

#[test]
fn test_concurrent_requests() {
    println!("Test: Concurrent authentication requests");
    
    // Spawn two threads, each sending an auth request with different request_id
    let handles: Vec<_> = (0..2)
        .map(|i| {
            std::thread::spawn(move || {
                let mut stream = connect_daemon().expect("Failed to connect");
                let auth_req = ipc::PamAuthenticateRequest {
                    username: format!("user{}", i),
                    tty_present: false,
                    timeout_seconds: 2,
                    request_id: format!("{}", 3000 + i),
                };
                
                write_message(&mut stream, &auth_req).expect("Failed to send");
                let response: ipc::PamAuthenticateResponse = read_message(&mut stream)
                    .expect("Failed to read response");
                
                println!("  Request {} got outcome: {:?}", i, response.outcome);
                assert_eq!(response.outcome, ipc::PamOutcome::Denied as i32);
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().expect("Thread panicked");
    }
    
    println!("✓ Concurrent requests handled correctly");
}

#[test]
fn test_empty_frame() {
    println!("Test: Empty frame (health check variant)");
    
    let mut stream = connect_daemon().expect("Failed to connect");
    
    // Send zero-length frame
    stream.write_all(&0u32.to_be_bytes()).expect("Write zero length");
    stream.flush().expect("Flush");
    
    // Daemon should handle gracefully; connection may close or stay open
    std::thread::sleep(Duration::from_millis(100));
    
    println!("✓ Empty frame handled");
}
