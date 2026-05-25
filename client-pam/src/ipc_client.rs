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

fn socket_path() -> String {
    #[cfg(feature = "dev-socket-override")]
    {
        if let Ok(override_path) = std::env::var("TAPAUTHD_SOCK") {
            return override_path;
        }
    }
    DEFAULT_SOCKET_PATH.to_string()
}

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
    /// Connect to tapauthd socket with configurable timeout for blocking operations.
    ///
    /// The timeout applies to connect, send, and receive operations to prevent
    /// PAM module hangs if the daemon is unresponsive.
    pub fn connect(timeout: Duration) -> Result<Self, IpcError> {
        let sock_path = socket_path();

        let stream = UnixStream::connect(&sock_path)?;

        // Set timeouts for all blocking operations
        // This prevents hanging if daemon becomes unresponsive
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        Ok(Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            expected_total: None,
        })
    }

    /// Connect and set nonblocking immediately (for poll/select driven loops).
    /// Does NOT set read/write timeouts since poll() handles all timing.
    pub fn connect_nonblocking() -> Result<Self, IpcError> {
        let sock_path = socket_path();

        // Connect and immediately set nonblocking for poll-based I/O
        // No timeouts - poll() in pam_logic.rs handles all timing
        let stream = UnixStream::connect(&sock_path)?;
        stream.set_nonblocking(true)?;

        Ok(Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            expected_total: None,
        })
    }

    /// Send a cancel request to the daemon with a short timeout.
    pub fn send_cancel(
        &mut self,
        reason: &str,
        request_id: &str,
    ) -> Result<ipc::PamAuthenticateResponse, IpcError> {
        let req = ipc::PamCancelRequest {
            reason: reason.to_string(),
            request_id: request_id.to_string(),
        };
        let envelope = ipc::IpcEnvelope {
            msg: Some(ipc::ipc_envelope::Msg::PamCancel(req)),
        };

        self.send_message(&envelope)?;
        // Short read timeout for cancel acknowledgement
        self.stream
            .set_read_timeout(Some(Duration::from_millis(750)))?;
        self.recv_response()
    }

    /// Get the raw file descriptor (for poll/select)
    pub fn fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// Set socket nonblocking flag
    pub fn set_nonblocking(&mut self, on: bool) -> Result<(), IpcError> {
        self.stream.set_nonblocking(on).map_err(IpcError::from)
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
        let envelope = ipc::IpcEnvelope {
            msg: Some(ipc::ipc_envelope::Msg::PamAuthenticate(req)),
        };

        self.send_message(&envelope)?;
        // Align with spec: wait exactly the session timeout
        self.stream
            .set_read_timeout(Some(Duration::from_secs(timeout_seconds as u64)))?;
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
        let envelope = ipc::IpcEnvelope {
            msg: Some(ipc::ipc_envelope::Msg::PamAuthenticate(req)),
        };
        tracing::trace!("Sending PamAuthenticateRequest [request_id={request_id}]");
        self.send_message(&envelope)
    }

    /// Nonblocking attempt to read a full response frame; Ok(None) if incomplete.
    pub fn try_read_response_nonblocking(
        &mut self,
    ) -> Result<Option<ipc::PamAuthenticateResponse>, IpcError> {
        let mut tmp = [0u8; 4096];
        loop {
            match self.stream.read(&mut tmp) {
                Ok(0) => break, // EOF or no more data
                Ok(n) => {
                    if let Some(slice) = tmp.get(..n) {
                        self.read_buf.extend_from_slice(slice);
                    } else {
                        return Err(IpcError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid read length",
                        )));
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    break
                }
                Err(e) => return Err(e.into()),
            }
        }

        if self.expected_total.is_none() {
            if self.read_buf.len() >= 4 {
                let len = u32::from_be_bytes([
                    *self.read_buf.first().ok_or(IpcError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid frame header",
                    )))?,
                    *self.read_buf.get(1).ok_or(IpcError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid frame header",
                    )))?,
                    *self.read_buf.get(2).ok_or(IpcError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid frame header",
                    )))?,
                    *self.read_buf.get(3).ok_or(IpcError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid frame header",
                    )))?,
                ]) as usize;
                if len > 1024 * 1024 {
                    return Err(IpcError::FrameTooLarge(len as u32));
                }
                self.expected_total = Some(4 + len);
            } else {
                return Ok(None);
            }
        }

        if let Some(total) = self.expected_total {
            if self.read_buf.len() >= total {
                let frame = self.read_buf.split_to(total);
                self.expected_total = None; // reset for next
                let data = frame.get(4..).ok_or(IpcError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too short",
                )))?;
                let resp = ipc::IpcEnvelope::decode(data)?;
                match resp.msg {
                    Some(ipc::ipc_envelope::Msg::PamResponse(response)) => {
                        return Ok(Some(response));
                    }
                    other => {
                        tracing::warn!(
                            "Unexpected IPC message type on PAM connection: {:?}",
                            other
                        );
                        return Err(IpcError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Unexpected IPC message type",
                        )));
                    }
                };
            }
        }
        Ok(None)
    }

    fn send_message<M: Message>(&mut self, msg: &M) -> Result<(), IpcError> {
        let encoded_len = msg.encoded_len();
        let msg_len = u32::try_from(encoded_len).map_err(|_| IpcError::FrameTooLarge(u32::MAX))?;

        // 4 bytes for length prefix + encoded message
        let mut buf = BytesMut::with_capacity(4 + encoded_len);

        // Write length prefix
        buf.put_u32(msg_len);

        msg.encode(&mut buf)?;

        self.stream.write_all(&buf)?;
        Ok(())
    }

    fn recv_response(&mut self) -> Result<ipc::PamAuthenticateResponse, IpcError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf);

        if len > 1024 * 1024 {
            return Err(IpcError::FrameTooLarge(len));
        }

        let mut data = vec![0u8; len as usize];
        self.stream.read_exact(&mut data)?;

        let envelope = ipc::IpcEnvelope::decode(&data[..])?;
        if let Some(ipc::ipc_envelope::Msg::PamResponse(response)) = envelope.msg {
            Ok(response)
        } else {
            Err(IpcError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected PamResponse in IpcEnvelope",
            )))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::io::Write as _;

    // Helper to build an IpcClient around an existing UnixStream (test-only)
    fn client_from_stream(stream: UnixStream) -> IpcClient {
        IpcClient {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            expected_total: None,
        }
    }

    #[test]
    fn frame_too_large_blocking() {
        let (mut a, b) = UnixStream::pair().expect("failed to create socket pair");
        let mut cli = client_from_stream(b);

        // Write BE length > 1 MiB; no payload needed as recv_response rejects on len alone
        let too_big: u32 = (1024 * 1024 + 1) as u32;
        let len_be = too_big.to_be_bytes();
        a.write_all(&len_be).expect("failed to write test data");

        let err = cli.recv_response().unwrap_err();
        match err {
            IpcError::FrameTooLarge(n) => assert!(n as usize > 1024 * 1024),
            other => panic!("unexpected error type: {other:?}"),
        }
    }

    #[test]
    fn frame_too_large_nonblocking() {
        let (mut a, b) = UnixStream::pair().expect("failed to create socket pair");
        // Set client nonblocking and wrap
        b.set_nonblocking(true).expect("failed to set nonblocking");
        let mut cli = client_from_stream(b);

        let too_big: u32 = (1024 * 1024 + 1) as u32;
        a.write_all(&too_big.to_be_bytes())
            .expect("failed to write test data");

        let err = cli
            .try_read_response_nonblocking()
            .expect_err("expected FrameTooLarge");
        match err {
            IpcError::FrameTooLarge(n) => assert!(n as usize > 1024 * 1024),
            other => panic!("unexpected error type: {other:?}"),
        }
    }
}
