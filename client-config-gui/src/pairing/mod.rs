pub mod session;

use crate::utils::{get_local_ipv4, get_local_ipv6};
use lazy_static::lazy_static;
use session::{PairingSessionState, PendingPairingState, SessionState};
use shared::{
    config::{ClientConfigManager, PairedServer},
    firewall::{FirewallGuard, Protocol},
    models::pairing::generate_pairing_url,
    protocol::ClientPairingSession,
};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

lazy_static! {
    pub static ref SESSION_STATE: Mutex<SessionState> = Mutex::new(SessionState::None);
}

pub async fn start_pairing() -> Result<(String, u16), String> {
    tracing::debug!("Starting pairing...");
    let config = ClientConfigManager::new();

    let keypair = config
        .load_keypair()
        .or_else(|_| config.generate_and_save_keypair())
        .map_err(|e| format!("Failed to load/generate keypair: {}", e))?;

    tracing::debug!("Getting local IP addresses...");
    let ipv4 = get_local_ipv4().ok_or("Failed to get IPv4 address")?;
    let ipv6 = get_local_ipv6().ok_or("Failed to get IPv6 address")?;
    tracing::debug!("IPv4: {}, IPv6: {}", ipv4, ipv6);

    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind TCP listener: {}", e))?;

    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get local address: {}", e))?
        .port();

    tracing::debug!("TCP listener bound to port {}", port);

    let firewall_guard = FirewallGuard::new(port, Protocol::Tcp)?;

    let session = ClientPairingSession::new(keypair.clone())
        .map_err(|e| format!("Failed to create pairing session: {}", e))?;
    let x25519_pubkey_hex = hex::encode(session.x25519_public_key());

    let url = generate_pairing_url(&x25519_pubkey_hex, port, Some(ipv4), Some(ipv6));
    tracing::debug!("Generated URL: {}", url);

    let pending_state = PendingPairingState {
        listener,
        firewall_guard,
        pairing_url: url.clone(),
    };

    *SESSION_STATE.lock().await = SessionState::Pending(pending_state);

    Ok((url, port))
}

pub async fn wait_for_pairing_connection(port: u16) -> Result<(String, u16), String> {
    use std::time::Duration;
    use tokio::time::timeout;

    tracing::debug!("Waiting for pairing connection on port {}...", port);

    let config = ClientConfigManager::new();

    let keypair = config
        .load_keypair()
        .map_err(|e| format!("Failed to load keypair: {}", e))?;

    let mut guard = SESSION_STATE.lock().await;

    let (listener, firewall_guard) = match std::mem::replace(&mut *guard, SessionState::None) {
        SessionState::Pending(state) => (state.listener, state.firewall_guard),
        _ => return Err("No pending session found".to_string()),
    };
    drop(guard);

    let accept_result = timeout(Duration::from_secs(300), listener.accept()).await;

    let (stream, _addr) = match accept_result {
        Ok(Ok((s, a))) => {
            tracing::debug!("Connection from {:?}", a);
            (s, a)
        }
        Ok(Err(e)) => return Err(format!("Accept error: {}", e)),
        Err(_) => return Err("Timeout waiting for connection".to_string()),
    };

    let mut session = ClientPairingSession::new(keypair.clone())
        .map_err(|e| format!("Failed to create pairing session: {}", e))?;

    let client_device_name = whoami::fallible::hostname().unwrap_or_else(|_| "Unknown".to_string());

    let (stream, server_public_key, server_device_name, sas) = session
        .initiate_pairing(stream, &client_device_name)
        .await
        .map_err(|e| format!("Pairing initiation failed: {}", e))?;

    tracing::debug!(
        "Pairing initiated. Server: {}, SAS: {}",
        server_device_name,
        &sas
    );

    let state = PairingSessionState {
        stream,
        session,
        server_public_key,
        server_device_name: server_device_name.clone(),
        keypair: keypair.clone(),
        _firewall_guard: firewall_guard,
    };

    *SESSION_STATE.lock().await = SessionState::Active(Box::new(state));

    Ok((shared::crypto::format_sas(&sas), port))
}

pub async fn complete_pairing(_port: u16) -> Result<String, String> {
    tracing::debug!("User confirmed SAS, completing pairing...");

    let config = ClientConfigManager::new();

    let username = crate::utils::elevation::get_username();

    tracing::info!("Pairing as user: {}", username);

    let mut state_guard = SESSION_STATE.lock().await;
    let state = match std::mem::replace(&mut *state_guard, SessionState::None) {
        SessionState::Active(s) => s,
        _ => return Err("No active pairing session in progress".to_string()),
    };
    drop(state_guard);

    let PairingSessionState {
        stream,
        mut session,
        server_public_key,
        server_device_name,
        keypair: _,
        _firewall_guard: _,
    } = *state;

    let csk = config
        .load_csk()
        .or_else(|_| config.generate_and_save_csk())
        .map_err(|e| format!("Failed to load/generate CSK: {}", e))?;

    tracing::debug!("Loaded/generated CSK");

    session
        .finish_pairing(stream, &csk, &username)
        .await
        .map_err(|e| format!("Pairing completion failed: {}", e))?;

    tracing::debug!("Pairing handshake complete");

    config
        .save_csk(&csk)
        .map_err(|e| format!("Paired on phone, but saving local key failed: {}. Ensure tapauthd is installed and the 'tapauthd' user and group exist, then retry pairing.", e))?;

    let server_hex = hex::encode(server_public_key);
    let paired_server = PairedServer {
        name: server_device_name,
        public_key: server_hex.clone(),
        paired_at: chrono::Utc::now(),
        allowed_users: vec![username],
    };

    config
        .add_paired_server(server_hex.clone(), paired_server)
        .map_err(|e| format!("Failed to save paired server: {}", e))?;

    tracing::debug!("Pairing complete!");

    Ok(server_hex)
}
