use bytes::{BufMut, BytesMut};
use prost::Message;
use shared::ipc::pb as ipc;
use std::io;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const DEFAULT_SOCKET: &str = "/run/tapauthd/tapauthd.sock";

pub async fn daemon_socket() -> io::Result<UnixStream> {
    let path = std::env::var("TAPAUTHD_SOCK").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());
    UnixStream::connect(Path::new(&path)).await
}

async fn write_framed(stream: &mut UnixStream, msg: &[u8]) -> io::Result<()> {
    let len = msg.len() as u32;
    let mut buf = BytesMut::with_capacity(4 + msg.len());
    buf.put_u32(len);
    buf.extend_from_slice(msg);
    stream.write_all(&buf).await
}

async fn read_framed(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

fn err_msg(resp: &ipc::AdminResponse) -> String {
    if resp.error_message.is_empty() {
        "Unknown error".to_string()
    } else {
        resp.error_message.clone()
    }
}

pub async fn send_admin_request(request: ipc::AdminRequest) -> Result<ipc::AdminResponse, String> {
    let envelope = ipc::IpcEnvelope {
        msg: Some(ipc::ipc_envelope::Msg::AdminRequest(request)),
    };

    let mut stream = daemon_socket()
        .await
        .map_err(|e| format!("Failed to connect to daemon: {}", e))?;

    let req_bytes = envelope.encode_to_vec();
    write_framed(&mut stream, &req_bytes)
        .await
        .map_err(|e| format!("Failed to send admin request: {}", e))?;

    let resp_bytes = read_framed(&mut stream)
        .await
        .map_err(|e| format!("Failed to read admin response: {}", e))?;

    ipc::AdminResponse::decode(&mut &resp_bytes[..])
        .map_err(|e| format!("Failed to decode admin response: {}", e))
}

pub async fn get_paired_servers() -> Result<Vec<ipc::PairedServerInfo>, String> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::GetServers(
            ipc::GetServersRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(err_msg(&response));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::GetServers(resp)) => Ok(resp.servers),
        _ => Err("Unexpected response type".to_string()),
    }
}

pub async fn start_pairing() -> Result<(String, u16), String> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::StartPairing(
            ipc::StartPairingRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(err_msg(&response));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::StartPairing(resp)) => Ok((resp.url, resp.port as u16)),
        _ => Err("Unexpected response type".to_string()),
    }
}

pub async fn wait_for_pairing(port: u32) -> Result<(String, u16), String> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::WaitForPairing(
            ipc::WaitForPairingRequest { port },
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(err_msg(&response));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::WaitForPairing(resp)) => {
            Ok((resp.sas_code, resp.port as u16))
        }
        _ => Err("Unexpected response type".to_string()),
    }
}

pub async fn complete_pairing(port: u32) -> Result<String, String> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::CompletePairing(
            ipc::CompletePairingRequest { port },
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(err_msg(&response));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::CompletePairing(resp)) => Ok(resp.server_hex),
        _ => Err("Unexpected response type".to_string()),
    }
}

pub async fn remove_device(public_key: String) -> Result<(), String> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::RemoveDevice(
            ipc::RemoveDeviceRequest { public_key },
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(err_msg(&response));
    }

    Ok(())
}

pub async fn rotate_csk() -> Result<(), String> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::RotateCsk(
            ipc::RotateCskRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(err_msg(&response));
    }

    Ok(())
}

pub async fn save_config(client_hostname: String, udp_port: u16) -> Result<(), String> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::SaveConfig(
            ipc::SaveConfigRequest {
                hostname: client_hostname,
                udp_port: udp_port as u32,
            },
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(err_msg(&response));
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn recover_tpm() -> Result<(), String> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::RecoverTpm(
            ipc::RecoverTpmRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(err_msg(&response));
    }

    Ok(())
}

pub async fn get_config() -> Result<(String, u16), String> {
    let request = ipc::AdminRequest {
        payload: Some(ipc::admin_request::Payload::GetConfig(
            ipc::GetConfigRequest {},
        )),
    };

    let response = send_admin_request(request).await?;

    if response.status != ipc::AdminStatus::AdminSuccess as i32 {
        return Err(err_msg(&response));
    }

    match response.payload {
        Some(ipc::admin_response::Payload::GetConfig(resp)) => {
            Ok((resp.hostname, resp.udp_port as u16))
        }
        _ => Err("Unexpected response type".to_string()),
    }
}
