//! Length-prefixed protobuf IPC over the tapauthd Unix socket: connect, frame,
//! send, and read a response. `IpcResponseReader` is the seam the poll loops are
//! generic over.
use bytes::BytesMut;
use prost::Message;
use shared::ipc::framing;
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
    /// The offending length when it was known; `u32::MAX` when the prefix or
    /// the encoded size was rejected by `shared::ipc::framing` before any
    /// length could be reported.
    FrameTooLarge(u32),
}

/// Synchronous IPC client for tapauthd communication.
pub struct IpcClient {
    stream: UnixStream,
    read_buf: BytesMut,
    expected_total: Option<usize>, // 4 (len) + payload
}

impl IpcClient {
    /// Connect, applying `timeout` to reads and writes so an unresponsive
    /// daemon cannot hang the PAM stack.
    pub fn connect(timeout: Duration) -> Result<Self, IpcError> {
        let sock_path = socket_path();

        let stream = UnixStream::connect(&sock_path)?;

        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        Ok(Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            expected_total: None,
        })
    }

    /// Connect nonblocking, without read/write timeouts: the poll loops own all
    /// timing.
    pub fn connect_nonblocking() -> Result<Self, IpcError> {
        let sock_path = socket_path();

        let stream = UnixStream::connect(&sock_path)?;
        stream.set_nonblocking(true)?;

        Ok(Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            expected_total: None,
        })
    }

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
        // The stream's own timeout is the caller's; the acknowledgement gets a
        // short one of its own.
        self.stream
            .set_read_timeout(Some(Duration::from_millis(750)))?;
        self.recv_response()
    }

    /// The raw file descriptor, for poll/select.
    pub fn fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    pub fn send_authenticate_start(
        &mut self,
        username: &str,
        tty_present: bool,
        timeout_seconds: u32,
        request_id: &str,
        pam_service: &str,
        process_name: &str,
    ) -> Result<(), IpcError> {
        let req = ipc::PamAuthenticateRequest {
            username: username.to_string(),
            tty_present,
            timeout_seconds,
            request_id: request_id.to_string(),
            pam_service: pam_service.to_string(),
            process_name: process_name.to_string(),
        };
        let envelope = ipc::IpcEnvelope {
            msg: Some(ipc::ipc_envelope::Msg::PamAuthenticate(req)),
        };
        tracing::trace!("Sending PamAuthenticateRequest [request_id={request_id}]");
        self.send_message(&envelope)
    }

    /// Nonblocking attempt to read a full response frame; `Ok(None)` if incomplete.
    pub fn try_read_response_nonblocking(
        &mut self,
    ) -> Result<Option<ipc::PamAuthenticateResponse>, IpcError> {
        let mut tmp = [0u8; 4096];
        loop {
            match self.stream.read(&mut tmp) {
                Ok(0) => break,
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
                let mut len_buf = [0u8; 4];
                len_buf.copy_from_slice(self.read_buf.get(..4).ok_or(IpcError::Io(
                    io::Error::new(io::ErrorKind::InvalidData, "invalid frame header"),
                ))?);
                // The shared decoder rejects anything above `MAX_FRAME_LEN`
                // before a body is reserved for it.
                let len =
                    framing::decode_len(len_buf).map_err(|_| IpcError::FrameTooLarge(u32::MAX))?;
                self.expected_total = Some(4 + len);
            } else {
                return Ok(None);
            }
        }

        if let Some(total) = self.expected_total {
            if self.read_buf.len() >= total {
                let frame = self.read_buf.split_to(total);
                self.expected_total = None;
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
        // The shared encoder refuses a body above `MAX_FRAME_LEN`, so the PAM
        // module never emits a frame any other endpoint would reject.
        let prefix =
            framing::encode_len(encoded_len).map_err(|_| IpcError::FrameTooLarge(u32::MAX))?;

        let mut buf = BytesMut::with_capacity(4 + encoded_len);

        buf.extend_from_slice(&prefix);

        msg.encode(&mut buf)?;

        self.stream.write_all(&buf)?;
        Ok(())
    }

    fn recv_response(&mut self) -> Result<ipc::PamAuthenticateResponse, IpcError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        // Rejected above `MAX_FRAME_LEN` before the body is reserved for it.
        let len = framing::decode_len(len_buf).map_err(|_| IpcError::FrameTooLarge(u32::MAX))?;

        let mut data = vec![0u8; len];
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

/// Minimal abstraction over the IPC transport, so the poll loops can be tested
/// with a mock backed by real file descriptors. It sits beside the client it
/// abstracts so `transaction::Armed` depends on the transport, not on `pam_logic`.
pub trait IpcResponseReader {
    fn fd(&self) -> RawFd;
    fn try_read_response_nonblocking(
        &mut self,
    ) -> Result<Option<ipc::PamAuthenticateResponse>, std::io::Error>;
    /// Best-effort cancellation of an in-flight authentication request.
    fn send_cancel(&mut self, reason: &str, request_id: &str) -> Result<(), std::io::Error>;
}

impl IpcResponseReader for IpcClient {
    fn fd(&self) -> RawFd {
        IpcClient::fd(self)
    }

    fn try_read_response_nonblocking(
        &mut self,
    ) -> Result<Option<ipc::PamAuthenticateResponse>, std::io::Error> {
        IpcClient::try_read_response_nonblocking(self)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn send_cancel(&mut self, reason: &str, request_id: &str) -> Result<(), std::io::Error> {
        IpcClient::send_cancel(self, reason, request_id)
            .map(|_| ())
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

// reason: test module; the crate root denies unwrap/expect/panic/indexing.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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

        // One byte past the shared cap; no payload needed as recv_response
        // rejects on the length alone.
        let too_big = framing::MAX_FRAME_LEN + 1;
        let len_be = (too_big as u32).to_be_bytes();
        a.write_all(&len_be).expect("failed to write test data");

        let err = cli.recv_response().unwrap_err();
        match err {
            IpcError::FrameTooLarge(n) => assert_eq!(n, u32::MAX),
            other => panic!("unexpected error type: {other:?}"),
        }
    }

    #[test]
    fn frame_too_large_nonblocking() {
        let (mut a, b) = UnixStream::pair().expect("failed to create socket pair");
        b.set_nonblocking(true).expect("failed to set nonblocking");
        let mut cli = client_from_stream(b);

        let too_big = framing::MAX_FRAME_LEN + 1;
        a.write_all(&(too_big as u32).to_be_bytes())
            .expect("failed to write test data");

        let err = cli
            .try_read_response_nonblocking()
            .expect_err("expected FrameTooLarge");
        match err {
            IpcError::FrameTooLarge(n) => assert_eq!(n, u32::MAX),
            other => panic!("unexpected error type: {other:?}"),
        }
    }

    /// The 1 MiB guard this module used to carry is gone: a frame the daemon
    /// may legitimately emit — anything up to the shared cap — is accepted by
    /// the reader, which then waits for the body instead of failing.
    #[test]
    fn frame_at_the_shared_cap_is_not_rejected() {
        let (mut a, b) = UnixStream::pair().expect("failed to create socket pair");
        b.set_nonblocking(true).expect("failed to set nonblocking");
        let mut cli = client_from_stream(b);

        a.write_all(&(framing::MAX_FRAME_LEN as u32).to_be_bytes())
            .expect("failed to write test data");

        assert!(
            cli.try_read_response_nonblocking()
                .expect("a frame at the cap must be accepted")
                .is_none(),
            "the reader must wait for the body rather than reject the length"
        );
    }

    /// The PAM writer and every reader bound at the same value: the writer
    /// refuses one byte past the shared cap instead of putting a frame on the
    /// socket that the daemon's `read_framed` would reject.
    #[test]
    fn pam_writer_refuses_a_frame_past_the_shared_cap() {
        let (mut a, b) = UnixStream::pair().expect("failed to create socket pair");
        a.set_nonblocking(true).expect("failed to set nonblocking");
        let mut cli = client_from_stream(b);

        let response = ipc::PamAuthenticateResponse {
            outcome: 0,
            detail: "x".repeat(framing::MAX_FRAME_LEN),
            challenge: Vec::new(),
        };

        let err = cli
            .send_message(&response)
            .expect_err("a body past the cap must not be written");
        match err {
            IpcError::FrameTooLarge(n) => assert_eq!(n, u32::MAX),
            other => panic!("unexpected error type: {other:?}"),
        }

        // Nothing reached the wire, so no reader is left waiting on a body the
        // writer refused to send.
        let mut buf = [0u8; 1];
        match a.read(&mut buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!("writer emitted bytes for a refused frame: {other:?}"),
        }
    }
}
