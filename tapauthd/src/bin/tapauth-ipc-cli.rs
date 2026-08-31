//! Admin & PAM IPC CLI tool for testing and administration.
//! Connects to tapauthd via Unix socket (supports TAPAUTHD_SOCK override).

use bytes::{BufMut, BytesMut};
use prost::Message;
use shared::ipc::pb as ipc;
use std::env;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

const DEFAULT_SOCKET: &str = "/run/tapauthd/tapauthd.sock";

fn socket_path() -> String {
    env::var("TAPAUTHD_SOCK").unwrap_or_else(|_| DEFAULT_SOCKET.to_string())
}

async fn daemon_socket() -> Result<UnixStream, Box<dyn std::error::Error>> {
    let path = socket_path();
    let stream = UnixStream::connect(Path::new(&path)).await?;
    Ok(stream)
}

async fn write_framed(
    stream: &mut UnixStream,
    msg: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let len = msg.len() as u32;
    let mut buf = BytesMut::with_capacity(4 + msg.len());
    buf.put_u32(len);
    buf.extend_from_slice(msg);
    stream.write_all(&buf).await?;
    Ok(())
}

async fn read_framed(stream: &mut UnixStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 10 * 1024 * 1024 {
        return Err("Frame too large".into());
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

async fn send_envelope(
    envelope: ipc::IpcEnvelope,
    read_timeout: Duration,
) -> Result<ipc::IpcEnvelope, Box<dyn std::error::Error>> {
    let mut stream = timeout(Duration::from_secs(10), daemon_socket()).await??;
    let req_bytes = envelope.encode_to_vec();
    timeout(
        Duration::from_secs(5),
        write_framed(&mut stream, &req_bytes),
    )
    .await??;
    let resp_bytes = timeout(read_timeout, read_framed(&mut stream)).await??;
    let resp_envelope = ipc::IpcEnvelope::decode(&resp_bytes[..])?;
    Ok(resp_envelope)
}

async fn send_admin(
    req: ipc::AdminRequest,
    read_timeout: Duration,
) -> Result<ipc::AdminResponse, Box<dyn std::error::Error>> {
    let envelope = ipc::IpcEnvelope {
        msg: Some(ipc::ipc_envelope::Msg::AdminRequest(req)),
    };
    let resp_envelope = send_envelope(envelope, read_timeout).await?;
    match resp_envelope.msg {
        Some(ipc::ipc_envelope::Msg::AdminResponse(resp)) => Ok(resp),
        _ => Err("Unexpected envelope type in response".into()),
    }
}

async fn send_pam_auth(
    username: String,
    timeout_secs: u32,
    request_id: String,
) -> Result<ipc::PamAuthenticateResponse, Box<dyn std::error::Error>> {
    let envelope = ipc::IpcEnvelope {
        msg: Some(ipc::ipc_envelope::Msg::PamAuthenticate(
            ipc::PamAuthenticateRequest {
                username,
                tty_present: false,
                timeout_seconds: timeout_secs,
                request_id,
            },
        )),
    };
    let resp_envelope =
        send_envelope(envelope, Duration::from_secs(timeout_secs as u64 + 10)).await?;
    match resp_envelope.msg {
        Some(ipc::ipc_envelope::Msg::PamResponse(resp)) => Ok(resp),
        _ => Err("Unexpected envelope type in response".into()),
    }
}

async fn send_pam_cancel(
    request_id: String,
    reason: String,
) -> Result<ipc::PamAuthenticateResponse, Box<dyn std::error::Error>> {
    let envelope = ipc::IpcEnvelope {
        msg: Some(ipc::ipc_envelope::Msg::PamCancel(ipc::PamCancelRequest {
            reason,
            request_id,
        })),
    };
    let resp_envelope = send_envelope(envelope, Duration::from_secs(10)).await?;
    match resp_envelope.msg {
        Some(ipc::ipc_envelope::Msg::PamResponse(resp)) => Ok(resp),
        _ => Err("Unexpected envelope type in response".into()),
    }
}

fn outcome_name(outcome: i32) -> &'static str {
    match ipc::PamOutcome::try_from(outcome) {
        Ok(ipc::PamOutcome::Success) => "SUCCESS",
        Ok(ipc::PamOutcome::Denied) => "DENIED",
        Ok(ipc::PamOutcome::Timeout) => "TIMEOUT",
        Ok(ipc::PamOutcome::Ignore) => "IGNORE",
        Ok(ipc::PamOutcome::Error) => "ERROR",
        Err(_) => "UNKNOWN",
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: tapauth-ipc-cli <command> [args...]");
        eprintln!("Commands:");
        eprintln!("  start-pairing");
        eprintln!("  wait-for-pairing <port>");
        eprintln!("  complete-pairing <port>");
        eprintln!("  get-servers");
        eprintln!("  remove-device <public_key_hex>");
        eprintln!("  set-transports --ble <true|false> --network <true|false>");
        eprintln!("  get-config");
        eprintln!("  pam-auth <username> [timeout_secs] [request_id]");
        eprintln!("  pam-cancel <request_id> [reason]");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "start-pairing" => {
            let req = ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::StartPairing(
                    ipc::StartPairingRequest {},
                )),
            };
            let resp = send_admin(req, Duration::from_secs(10)).await?;
            if resp.status != ipc::AdminStatus::AdminSuccess as i32 {
                eprintln!("ERROR: {}", resp.error_message);
                std::process::exit(1);
            }
            if let Some(ipc::admin_response::Payload::StartPairing(p)) = resp.payload {
                println!("PORT={}", p.port);
                println!("URL={}", p.url);
            }
        }
        "wait-for-pairing" => {
            if args.len() < 3 {
                eprintln!("Usage: tapauth-ipc-cli wait-for-pairing <port>");
                std::process::exit(1);
            }
            let port: u32 = args[2].parse()?;
            let req = ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::WaitForPairing(
                    ipc::WaitForPairingRequest { port },
                )),
            };
            let resp = send_admin(req, Duration::from_secs(60)).await?;
            if resp.status != ipc::AdminStatus::AdminSuccess as i32 {
                eprintln!("ERROR: {}", resp.error_message);
                std::process::exit(1);
            }
            if let Some(ipc::admin_response::Payload::WaitForPairing(p)) = resp.payload {
                println!("SAS={}", p.sas_code);
                println!("PORT={}", p.port);
            }
        }
        "complete-pairing" => {
            if args.len() < 3 {
                eprintln!("Usage: tapauth-ipc-cli complete-pairing <port>");
                std::process::exit(1);
            }
            let port: u32 = args[2].parse()?;
            let req = ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::CompletePairing(
                    ipc::CompletePairingRequest { port },
                )),
            };
            let resp = send_admin(req, Duration::from_secs(30)).await?;
            if resp.status != ipc::AdminStatus::AdminSuccess as i32 {
                eprintln!("ERROR: {}", resp.error_message);
                std::process::exit(1);
            }
            if let Some(ipc::admin_response::Payload::CompletePairing(p)) = resp.payload {
                println!("SERVER_HEX={}", p.server_hex);
            }
        }
        "get-servers" => {
            let req = ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::GetServers(
                    ipc::GetServersRequest {},
                )),
            };
            let resp = send_admin(req, Duration::from_secs(10)).await?;
            if resp.status != ipc::AdminStatus::AdminSuccess as i32 {
                eprintln!("ERROR: {}", resp.error_message);
                std::process::exit(1);
            }
            if let Some(ipc::admin_response::Payload::GetServers(p)) = resp.payload {
                println!("COUNT={}", p.servers.len());
                for s in p.servers {
                    println!(
                        "SERVER: name={}, key={}, users={:?}",
                        s.name, s.public_key, s.allowed_users
                    );
                }
            }
        }
        "remove-device" => {
            if args.len() < 3 {
                eprintln!("Usage: tapauth-ipc-cli remove-device <public_key_hex>");
                std::process::exit(1);
            }
            let public_key = args[2].clone();
            let req = ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::RemoveDevice(
                    ipc::RemoveDeviceRequest { public_key },
                )),
            };
            let resp = send_admin(req, Duration::from_secs(10)).await?;
            if resp.status != ipc::AdminStatus::AdminSuccess as i32 {
                eprintln!("ERROR: {}", resp.error_message);
                std::process::exit(1);
            }
            println!("REMOVED=true");
        }
        "set-transports" => {
            let mut ble = None;
            let mut network = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--ble" => {
                        if i + 1 >= args.len() {
                            eprintln!("Missing value for --ble");
                            std::process::exit(1);
                        }
                        ble = Some(args[i + 1].parse::<bool>()?);
                        i += 2;
                    }
                    "--network" => {
                        if i + 1 >= args.len() {
                            eprintln!("Missing value for --network");
                            std::process::exit(1);
                        }
                        network = Some(args[i + 1].parse::<bool>()?);
                        i += 2;
                    }
                    _ => i += 1,
                }
            }

            let cfg_req = ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::GetConfig(
                    ipc::GetConfigRequest {},
                )),
            };
            let cfg_resp = send_admin(cfg_req, Duration::from_secs(10)).await?;
            if cfg_resp.status != ipc::AdminStatus::AdminSuccess as i32 {
                // Refusing to fall back to defaults here: SaveConfig persists the
                // whole config, so guessing hostname/udp_port could clobber the
                // daemon's real values.
                eprintln!(
                    "ERROR: could not read current config: {}",
                    cfg_resp.error_message
                );
                std::process::exit(1);
            }
            let (hostname, udp_port) = match cfg_resp.payload {
                Some(ipc::admin_response::Payload::GetConfig(c)) => (c.hostname, c.udp_port),
                _ => {
                    eprintln!("ERROR: unexpected response payload from get-config");
                    std::process::exit(1);
                }
            };

            let req = ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::SaveConfig(
                    ipc::SaveConfigRequest {
                        hostname,
                        udp_port,
                        enable_ble: ble,
                        enable_network: network,
                    },
                )),
            };
            let resp = send_admin(req, Duration::from_secs(10)).await?;
            if resp.status != ipc::AdminStatus::AdminSuccess as i32 {
                eprintln!("ERROR: {}", resp.error_message);
                std::process::exit(1);
            }
            println!("CONFIG_SAVED=true");
        }
        "get-config" => {
            let req = ipc::AdminRequest {
                payload: Some(ipc::admin_request::Payload::GetConfig(
                    ipc::GetConfigRequest {},
                )),
            };
            let resp = send_admin(req, Duration::from_secs(10)).await?;
            if resp.status != ipc::AdminStatus::AdminSuccess as i32 {
                eprintln!("ERROR: {}", resp.error_message);
                std::process::exit(1);
            }
            if let Some(ipc::admin_response::Payload::GetConfig(c)) = resp.payload {
                println!("HOSTNAME={}", c.hostname);
                println!("UDP_PORT={}", c.udp_port);
                println!("ENABLE_BLE={}", c.enable_ble);
                println!("ENABLE_NETWORK={}", c.enable_network);
            }
        }
        "pam-auth" => {
            if args.len() < 3 {
                eprintln!("Usage: tapauth-ipc-cli pam-auth <username> [timeout_secs] [request_id]");
                std::process::exit(1);
            }
            let user = args[2].clone();
            let timeout_secs = if args.len() >= 4 {
                args[3].parse::<u32>()?
            } else {
                30
            };
            let request_id = if args.len() >= 5 {
                args[4].clone()
            } else {
                format!("test-{}", std::process::id())
            };
            // Print the request id before blocking so orchestrators can cancel it.
            println!("REQUEST_ID={}", request_id);
            let resp = send_pam_auth(user, timeout_secs, request_id).await?;
            println!("OUTCOME={}", outcome_name(resp.outcome));
            println!("DETAIL={}", resp.detail);
            if resp.outcome != 0 {
                std::process::exit(resp.outcome);
            }
        }
        "pam-cancel" => {
            if args.len() < 3 {
                eprintln!("Usage: tapauth-ipc-cli pam-cancel <request_id> [reason]");
                std::process::exit(1);
            }
            let request_id = args[2].clone();
            let reason = if args.len() >= 4 {
                args[3].clone()
            } else {
                "cli-cancel".to_string()
            };
            let resp = send_pam_cancel(request_id, reason).await?;
            println!("OUTCOME={}", outcome_name(resp.outcome));
            println!("DETAIL={}", resp.detail);
        }
        other => {
            eprintln!("Unknown command: {}", other);
            std::process::exit(1);
        }
    }

    Ok(())
}
