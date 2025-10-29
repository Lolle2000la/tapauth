use shared::{
    config::ClientConfigManager,
    crypto::{ClientSymmetricKey, CryptoError, Ed25519KeyPair},
    network::get_session_timeout,
    protocol::{
        messages::*,
        packet::*,
        pb::{wrapper_message, EncryptedPacket},
        ProtocolError,
    },
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::transport::{ReceiveResult, Transport, UdpTransport};

#[cfg(feature = "ble")]
use crate::transport::BleTransport;

#[cfg(feature = "ble")]
use shared::crypto::generate_current_temporal_identifier_ble;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Configuration error: {0}")]
    Config(#[from] shared::config::ConfigError),
    #[error("Network error: {0}")]
    Network(#[from] shared::network::NetworkError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Authentication timeout")]
    Timeout,
    #[error("Authentication denied")]
    Denied,
    #[error("No paired devices")]
    NoPairedDevices,
    #[error("Failed to initialize: {0}")]
    InitError(String),
    #[error("BLE error: {0}")]
    BleError(String),
}

#[derive(Clone)]
pub struct AuthenticationClient {
    config_manager: Arc<ClientConfigManager>,
    keypair: Ed25519KeyPair,
    csk: ClientSymmetricKey,
    username: String,
    hostname: String,
    challenge: [u8; 32],
}

impl AuthenticationClient {
    /// Create a new authentication client
    pub fn new(username: String) -> Result<Self, AuthError> {
        let config_manager = ClientConfigManager::new();

        // Load keypair and CSK
        let keypair = config_manager
            .load_keypair()
            .map_err(|e| AuthError::InitError(format!("Failed to load keypair: {}", e)))?;

        let csk = config_manager
            .load_csk()
            .map_err(|e| AuthError::InitError(format!("Failed to load CSK: {}", e)))?;

        let config = config_manager.load_config()?;
        let hostname = config.hostname;

        // Generate challenge
        let mut challenge = [0u8; 32];
        getrandom::fill(&mut challenge).expect("Failed to generate challenge");

        Ok(Self {
            config_manager: Arc::new(config_manager),
            keypair,
            csk,
            username,
            hostname,
            challenge,
        })
    }

    /// Run the authentication flow
    pub async fn authenticate(&self) -> Result<(), AuthError> {
        // Check if we have any paired devices
        let paired_servers = self.config_manager.load_paired_servers()?;
        if paired_servers.is_empty() {
            return Err(AuthError::NoPairedDevices);
        }

        // Filter servers that are allowed to authenticate this user
        let allowed_servers: Vec<_> = paired_servers
            .iter()
            .filter(|(_, server)| server.is_user_allowed(&self.username))
            .collect();

        if allowed_servers.is_empty() {
            tracing::warn!("No paired servers authorized for user: {}", self.username);
            return Err(AuthError::NoPairedDevices);
        }

        tracing::info!(
            "{} server(s) authorized for user {}",
            allowed_servers.len(),
            self.username
        );

        // Create the authentication request
        let request = create_auth_request_with_challenge(
            &self.keypair,
            &self.username,
            &self.hostname,
            &self.challenge,
        )?;
        let wrapper = wrap_auth_request(request);
        let packet = create_encrypted_packet_with_csk_nonce(&self.csk, &wrapper)?;

        // Try authentication with available transports
        #[cfg(feature = "ble")]
        {
            self.try_parallel_authentication(&packet).await
        }

        #[cfg(not(feature = "ble"))]
        {
            let config = self.config_manager.load_config()?;
            let mut transport = UdpTransport::new(config.udp_port).await?;
            self.authenticate_with_transport(&mut transport, &packet)
                .await
        }
    }

    #[cfg(feature = "ble")]
    async fn try_parallel_authentication(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use tokio::select;

        let temporal_id = generate_current_temporal_identifier_ble(&self.csk)?;
        let timeout = get_session_timeout();

        tracing::info!("Starting parallel discovery over UDP and BLE");

        // Spawn BLE task
        let self_ble = self.clone();
        let packet_ble = packet.clone();
        let config_manager = self.config_manager.clone();
        let keypair = Arc::new(self.keypair.clone());
        let challenge = self.challenge;
        let mut ble_handle = tokio::spawn(async move {
            match BleTransport::new(temporal_id, timeout, config_manager, keypair, challenge).await
            {
                Ok(mut transport) => {
                    self_ble
                        .authenticate_with_transport(&mut transport, &packet_ble)
                        .await
                }
                Err(e) => Err(e),
            }
        });

        // Spawn UDP task
        let self_udp = self.clone();
        let packet_udp = packet.clone();
        let mut udp_handle = tokio::spawn(async move {
            let config = self_udp.config_manager.load_config().unwrap();
            match UdpTransport::new(config.udp_port).await {
                Ok(mut transport) => {
                    self_udp
                        .authenticate_with_transport(&mut transport, &packet_udp)
                        .await
                }
                Err(e) => Err(e),
            }
        });

        let mut ble_completed = false;
        let mut udp_completed = false;
        let mut udp_result: Option<Result<(), AuthError>> = None;

        loop {
            select! {
                result = &mut ble_handle, if !ble_completed => {
                    ble_completed = true;
                    match result {
                        Ok(Ok(())) => {
                            tracing::info!("BLE authentication succeeded");
                            udp_handle.abort();
                            return Ok(());
                        }
                        Ok(Err(AuthError::Denied)) => {
                            tracing::warn!("BLE authentication denied");
                            if udp_completed {
                                return udp_result.unwrap_or(Err(AuthError::Denied));
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::debug!("BLE authentication failed: {}", e);
                        }
                        Err(e) => {
                            tracing::debug!("BLE task panicked: {}", e);
                        }
                    }
                }
                result = &mut udp_handle, if !udp_completed => {
                    udp_completed = true;
                    match result {
                        Ok(Ok(())) => {
                            tracing::info!("UDP authentication succeeded");
                            ble_handle.abort();
                            return Ok(());
                        }
                        Ok(Err(e)) => {
                            udp_result = Some(Err(e));
                        }
                        Err(e) => {
                            tracing::debug!("UDP task panicked: {}", e);
                            udp_result = Some(Err(AuthError::Network(
                                shared::network::NetworkError::Io(std::io::Error::other(
                                    format!("UDP task failed: {}", e),
                                )),
                            )));
                        }
                    }
                }
            }

            if ble_completed && udp_completed {
                tracing::warn!("Both BLE and UDP authentication failed");
                return udp_result.unwrap_or(Err(AuthError::Timeout));
            }
        }
    }

    /// Authenticate using a generic transport (request/response pattern)
    async fn authenticate_with_transport(
        &self,
        transport: &mut impl Transport,
        packet: &EncryptedPacket,
    ) -> Result<(), AuthError> {
        tracing::info!("Starting authentication via {}", transport.name());

        let start = Instant::now();
        tracing::trace!(
            "authenticate_with_transport started for {} at {:?}",
            transport.name(),
            start
        );
        let timeout = get_session_timeout();
        let mut attempt = 0u32;
        let mut confirmation_sent = false;
        let mut final_result: Option<Result<(), AuthError>> = None;

        loop {
            if start.elapsed() >= timeout {
                return final_result.unwrap_or(Err(AuthError::Timeout));
            }

            // If we already have a result, drain remaining packets briefly then return
            if let Some(result) = final_result.take() {
                match tokio::time::timeout(
                    Duration::from_millis(100),
                    transport.receive_response(Duration::from_millis(50)),
                )
                .await
                {
                    Ok(Ok(ReceiveResult::Response(_, _))) => {
                        tracing::trace!("Draining additional packet");
                        final_result = Some(result);
                        continue;
                    }
                    _ => {
                        tracing::debug!("No more packets, returning result");
                        return result;
                    }
                }
            }

            // Send request
            let send_start = Instant::now();
            tracing::trace!(
                "Calling transport.send_request (transport={})",
                transport.name()
            );
            transport.send_request(packet).await?;
            tracing::trace!(
                "transport.send_request completed, elapsed={:?}",
                send_start.elapsed()
            );

            // Wait for response with exponential backoff
            let retry_interval = shared::network::get_client_retry_interval(attempt);

            loop {
                let recv_start = Instant::now();
                tracing::trace!(
                    "Calling transport.receive_response (transport={}, timeout={:?})",
                    transport.name(),
                    retry_interval
                );
                match transport.receive_response(retry_interval).await? {
                    ReceiveResult::Response(response_packet, server_addr) => {
                        tracing::trace!(
                            "transport.receive_response returned Response, elapsed={:?}",
                            recv_start.elapsed()
                        );
                        // Process response
                        let proc_start = Instant::now();
                        match self.process_response(&response_packet, server_addr).await {
                            Ok(true) => {
                                tracing::trace!(
                                    "process_response accepted, elapsed={:?}",
                                    proc_start.elapsed()
                                );
                                // Authentication granted
                                if !confirmation_sent {
                                    let confirmation =
                                        create_grant_confirmation(&self.keypair, &self.challenge)?;
                                    let wrapper = wrap_grant_confirmation(confirmation);
                                    let conf_packet = create_encrypted_packet_with_csk_nonce(
                                        &self.csk, &wrapper,
                                    )?;

                                    transport.send_confirmation(&conf_packet).await?;
                                    confirmation_sent = true;
                                }
                                final_result = Some(Ok(()));
                                // Continue loop to drain packets
                                break;
                            }
                            Ok(false) => {
                                tracing::trace!(
                                    "process_response denied, elapsed={:?}",
                                    proc_start.elapsed()
                                );
                                // Authentication denied
                                if !confirmation_sent {
                                    let confirmation =
                                        create_grant_confirmation(&self.keypair, &self.challenge)?;
                                    let wrapper = wrap_grant_confirmation(confirmation);
                                    let conf_packet = create_encrypted_packet_with_csk_nonce(
                                        &self.csk, &wrapper,
                                    )?;

                                    transport.send_confirmation(&conf_packet).await?;
                                    confirmation_sent = true;
                                }
                                final_result = Some(Err(AuthError::Denied));
                                break;
                            }
                            Err(e) => {
                                tracing::warn!("Failed to process response: {}", e);
                                // Continue waiting for valid response
                            }
                        }
                    }
                    ReceiveResult::Timeout => {
                        attempt += 1;
                        break;
                    }
                }
            }
        }
    }

    /// Process a response packet from a server
    async fn process_response(
        &self,
        packet: &EncryptedPacket,
        server_addr: SocketAddr,
    ) -> Result<bool, AuthError> {
        // Decrypt the packet
        let wrapper = decrypt_encrypted_packet_with_csk_nonce(&self.csk, packet)?;

        tracing::info!(
            "Received message from {}: {:?}",
            server_addr,
            match &wrapper.payload {
                Some(wrapper_message::Payload::AuthGrant(_)) => "AuthGrant",
                Some(wrapper_message::Payload::AuthDenial(_)) => "AuthDenial",
                _ => "Unknown",
            }
        );

        match wrapper.payload {
            Some(wrapper_message::Payload::AuthGrant(grant)) => {
                let paired_servers = self.config_manager.load_paired_servers()?;

                for (_id, server) in paired_servers.iter() {
                    let pub_key_bytes = hex::decode(&server.public_key)
                        .map_err(|_| AuthError::Protocol(ProtocolError::InvalidMessageFormat))?;

                    if pub_key_bytes.len() != 32 {
                        continue;
                    }

                    let mut pub_key = [0u8; 32];
                    pub_key.copy_from_slice(&pub_key_bytes);

                    if verify_auth_grant(&grant, &self.challenge, &pub_key).is_ok() {
                        tracing::info!("Authentication granted by server: {}", server.name);
                        return Ok(true);
                    }
                }

                Err(AuthError::Protocol(ProtocolError::InvalidSignature))
            }
            Some(wrapper_message::Payload::AuthDenial(denial)) => {
                let paired_servers = self.config_manager.load_paired_servers()?;

                for (_id, server) in paired_servers.iter() {
                    let pub_key_bytes = hex::decode(&server.public_key)
                        .map_err(|_| AuthError::Protocol(ProtocolError::InvalidMessageFormat))?;

                    if pub_key_bytes.len() != 32 {
                        continue;
                    }

                    let mut pub_key = [0u8; 32];
                    pub_key.copy_from_slice(&pub_key_bytes);

                    if verify_auth_denial(&denial, &pub_key).is_ok() {
                        tracing::info!("Authentication denied by server: {}", server.name);
                        return Ok(false);
                    }
                }

                Err(AuthError::Protocol(ProtocolError::InvalidSignature))
            }
            _ => Err(AuthError::Protocol(ProtocolError::InvalidMessageFormat)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_client_creation_fails_without_config() {
        let result = AuthenticationClient::new("testuser".to_string());
        assert!(result.is_err());
    }
}
