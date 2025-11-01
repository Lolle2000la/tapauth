/// Simple IPC client helpers for PAM to communicate with tapauthd.
///
/// Provides synchronous wrappers over length-delimited protobuf IPC.

use bytes::{BufMut, BytesMut};
use prost::Message;
use shared::ipc::pb as ipc;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const DEFAULT_SOCKET_PATH: &str = "/run/tapauthd/tapauthd.sock";
const IO_TIMEOUT_MS: u64 = 2000; // write and short reads

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("prost encode: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("prost decode: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(u32),
}

/// Synchronous IPC client for tapauthd communication.
pub struct IpcClient {
    stream: UnixStream,
}

impl IpcClient {
    /// Connect to tapauthd socket.
    pub fn connect() -> Result<Self, IpcError> {
        let sock_path = std::env::var("TAPAUTHD_SOCK").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
        
        // Note: UnixStream::connect is blocking, but typically fast for local sockets
        let stream = UnixStream::connect(&sock_path)?;
        
        stream.set_read_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)))?;
        stream.set_write_timeout(Some(Duration::from_millis(IO_TIMEOUT_MS)))?;
        
        Ok(Self { stream })
    }

    /// Send a cancel request to the daemon.
    pub fn send_cancel(&mut self, reason: &str, request_id: &str) -> Result<ipc::PamAuthenticateResponse, IpcError> {
        let req = ipc::PamCancelRequest {
            reason: reason.to_string(),
            request_id: request_id.to_string(),
        };
        
        self.send_message(&req)?;
        // Short read timeout for cancel acknowledgement
        self.stream
            .set_read_timeout(Some(Duration::from_millis(750)))?;
        self.recv_response()
    }

    /// Send an authenticate request to the daemon.
    pub fn send_authenticate(
        &mut self,
        username: &str,
        tty_present: bool,
        timeout_seconds: u32,
        request_id: &str,
    ) -> Result<ipc::PamAuthenticateResponse, IpcError> {
        let req = ipc::PamAuthenticateRequest {
            username: username.to_string(),
            tty_present,
            timeout_seconds,
            request_id: request_id.to_string(),
        };

        self.send_message(&req)?;
        // Allow the daemon enough time to complete the auth flow. Add a small buffer.
        let total = (timeout_seconds as u64).saturating_add(5);
        self.stream
            .set_read_timeout(Some(Duration::from_secs(total)))?;
        self.recv_response()
    }

    fn send_message<M: Message>(&mut self, msg: &M) -> Result<(), IpcError> {
        let mut buf = BytesMut::with_capacity(256);
        
        // Encode message to get length first
        let msg_bytes = msg.encode_to_vec();
        let msg_len = msg_bytes.len() as u32;
        
        // Write length prefix (u32 BE)
        buf.put_u32(msg_len);
        // Write message
        buf.extend_from_slice(&msg_bytes);
        
        self.stream.write_all(&buf)?;
        Ok(())
    }

    fn recv_response(&mut self) -> Result<ipc::PamAuthenticateResponse, IpcError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf);
        
        if len > 10 * 1024 * 1024 {
            return Err(IpcError::FrameTooLarge(len));
        }
        
        let mut data = vec![0u8; len as usize];
        self.stream.read_exact(&mut data)?;
        
        Ok(ipc::PamAuthenticateResponse::decode(&data[..])?)
    }
}
