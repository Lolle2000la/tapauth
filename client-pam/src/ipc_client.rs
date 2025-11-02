/// Simple IPC client helpers for PAM to communicate with tapauthd.
///
/// Provides synchronous wrappers over length-delimited protobuf IPC.

use bytes::{BufMut, BytesMut};
use prost::Message;
use shared::ipc::pb as ipc;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const DEFAULT_SOCKET_PATH: &str = "/run/tapauthd/tapauthd.sock";

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
    // Buffer for assembling length-prefixed frames in nonblocking mode
    read_buf: BytesMut,
    expected_total: Option<usize>, // 4 (len) + payload
}

impl IpcClient {
    /// Connect to tapauthd socket.
    pub fn connect() -> Result<Self, IpcError> {
        let sock_path = std::env::var("TAPAUTHD_SOCK").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string());
        
        // Note: UnixStream::connect is blocking, but typically fast for local sockets
        let stream = UnixStream::connect(&sock_path)?;
        Ok(Self { stream, read_buf: BytesMut::with_capacity(4096), expected_total: None })
    }

    /// Connect and set nonblocking immediately (for poll/select driven loops)
    pub fn connect_nonblocking() -> Result<Self, IpcError> {
        let mut cli = Self::connect()?;
        cli.set_nonblocking(true)?;
        Ok(cli)
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

    /// Get the raw file descriptor (for poll/select)
    pub fn fd(&self) -> RawFd { self.stream.as_raw_fd() }

    /// Set socket nonblocking flag
    pub fn set_nonblocking(&mut self, on: bool) -> Result<(), IpcError> { self.stream.set_nonblocking(on).map_err(IpcError::from) }

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

    /// Start authenticate request without waiting (for polling caller)
    pub fn send_authenticate_start(
        &mut self,
        username: &str,
        tty_present: bool,
        timeout_seconds: u32,
        request_id: &str,
    ) -> Result<(), IpcError> {
        let req = ipc::PamAuthenticateRequest {
            username: username.to_string(),
            tty_present,
            timeout_seconds,
            request_id: request_id.to_string(),
        };
        self.send_message(&req)
    }

    /// Nonblocking attempt to read a full response frame; Ok(None) if incomplete.
    pub fn try_read_response_nonblocking(&mut self) -> Result<Option<ipc::PamAuthenticateResponse>, IpcError> {
        let mut tmp = [0u8; 4096];
        loop {
            match self.stream.read(&mut tmp) {
                Ok(0) => break, // EOF or no more data
                Ok(n) => self.read_buf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted => break,
                Err(e) => return Err(e.into()),
            }
        }

        if self.expected_total.is_none() {
            if self.read_buf.len() >= 4 {
                let len = u32::from_be_bytes([
                    self.read_buf[0], self.read_buf[1], self.read_buf[2], self.read_buf[3]
                ]) as usize;
                if len > 10 * 1024 * 1024 { return Err(IpcError::FrameTooLarge(len as u32)); }
                self.expected_total = Some(4 + len);
            } else {
                return Ok(None);
            }
        }

        if let Some(total) = self.expected_total {
            if self.read_buf.len() >= total {
                let frame = self.read_buf.split_to(total);
                self.expected_total = None; // reset for next
                let data = &frame[4..];
                let resp = ipc::PamAuthenticateResponse::decode(data)?;
                return Ok(Some(resp));
            }
        }
        Ok(None)
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
