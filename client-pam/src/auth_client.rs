use shared::{
    config::ClientConfigManager,
    crypto::{generate_current_temporal_identifier, ClientSymmetricKey, Ed25519KeyPair},
    network::{
        create_broadcast_socket, get_client_retry_interval, get_session_timeout,
        send_udp_broadcast, send_udp_multicast, try_receive_udp_packet, DEFAULT_UDP_PORT,
        IPV6_MULTICAST_ADDR,
    },
    protocol::{
        messages::*,
        packet::*,
        pb::{wrapper_message, EncryptedPacket, WrapperMessage},
        ProtocolError,
    },
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Configuration error: {0}")]
    Config(#[from] shared::config::ConfigError),
    #[error("Network error: {0}")]
    Network(#[from] shared::network::NetworkError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Authentication timeout")]
    Timeout,
    #[error("Authentication denied")]
    Denied,
    #[error("No paired devices")]
    NoPairedDevices,
    #[error("Failed to initialize: {0}")]
    InitError(String),
}

pub struct AuthenticationClient {
    config_manager: ClientConfigManager,
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
        getrandom::getrandom(&mut challenge).expect("Failed to generate challenge");

        Ok(Self {
            config_manager,
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

        // Create the authentication request
        let request = create_auth_request(&self.keypair, &self.username, &self.hostname)?;
        let wrapper = wrap_auth_request(request);

        // Create encrypted packet
        // Note: For authentication, we use a static nonce derived from CSK only,
        // since the challenge is INSIDE the encrypted message and can't be used
        // to derive the decryption nonce (chicken-egg problem).
        let packet =
            create_encrypted_packet_with_csk_nonce(&self.csk, &wrapper)?;

        // Start parallel discovery: UDP + BLE
        let udp_result = self.try_udp_authentication(&packet).await;

        match udp_result {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!("UDP authentication failed: {}", e);
                Err(e)
            }
        }
    }

    /// Try authentication over UDP (IPv4 broadcast + IPv6 multicast)
    async fn try_udp_authentication(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        let socket = create_broadcast_socket()?;
        let config = self.config_manager.load_config()?;
        let port = config.udp_port;

        let start = Instant::now();
        let timeout = get_session_timeout();
        let mut attempt = 0u32;
        let mut confirmation_sent = false;

        loop {
            if start.elapsed() >= timeout {
                return Err(AuthError::Timeout);
            }

            // Send broadcast on IPv4
            if let Err(e) = send_udp_broadcast(&socket, port, packet) {
                tracing::warn!("Failed to send IPv4 broadcast: {}", e);
            }

            // Send multicast on IPv6
            if let Err(e) = send_udp_multicast(&socket, IPV6_MULTICAST_ADDR, port, packet) {
                tracing::warn!("Failed to send IPv6 multicast: {}", e);
            }

            // Wait for response
            let retry_interval = get_client_retry_interval(attempt);
            match try_receive_udp_packet(&socket, retry_interval)? {
                Some((response_packet, server_addr)) => {
                    // Try to decrypt and process response
                    match self.process_response(&response_packet, server_addr).await {
                        Ok(true) => {
                            // Authentication granted
                            if !confirmation_sent {
                                self.send_confirmation(&socket, port).await?;
                                confirmation_sent = true;
                            }

                            // Send cancel to other servers
                            self.send_cancel_broadcast(&socket, port).await?;

                            return Ok(());
                        }
                        Ok(false) => {
                            // Authentication denied
                            return Err(AuthError::Denied);
                        }
                        Err(e) => {
                            tracing::debug!("Failed to process response: {}", e);
                            // Continue trying - might be from wrong server or corrupted
                        }
                    }
                }
                None => {
                    // No response yet, retry
                    attempt += 1;
                }
            }
        }
    }

    /// Process a response packet from a server
    async fn process_response(
        &self,
        packet: &EncryptedPacket,
        _server_addr: SocketAddr,
    ) -> Result<bool, AuthError> {
        // Decrypt the packet
        let wrapper =
            decrypt_encrypted_packet(&self.csk, &self.challenge, b"auth_response", packet)?;

        // Check what kind of response we got
        match wrapper.payload {
            Some(wrapper_message::Payload::AuthGrant(grant)) => {
                // Verify the grant
                // We need to find which server sent this by checking signatures
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
                // Verify the denial
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

    /// Send confirmation to server
    async fn send_confirmation(
        &self,
        socket: &std::net::UdpSocket,
        port: u16,
    ) -> Result<(), AuthError> {
        let confirmation = create_grant_confirmation(&self.keypair, &self.challenge)?;
        let wrapper = wrap_grant_confirmation(confirmation);
        let packet =
            create_encrypted_packet(&self.csk, &self.challenge, b"grant_confirmation", &wrapper)?;

        // Send on both IPv4 and IPv6
        send_udp_broadcast(socket, port, &packet)?;
        send_udp_multicast(socket, IPV6_MULTICAST_ADDR, port, &packet)?;

        Ok(())
    }

    /// Send cancel broadcast to all servers
    async fn send_cancel_broadcast(
        &self,
        socket: &std::net::UdpSocket,
        port: u16,
    ) -> Result<(), AuthError> {
        let cancel = create_auth_cancel(&self.keypair, &self.challenge)?;
        let wrapper = wrap_auth_cancel(cancel);
        let packet = create_encrypted_packet(&self.csk, &self.challenge, b"auth_cancel", &wrapper)?;

        // Send on both IPv4 and IPv6
        send_udp_broadcast(socket, port, &packet)?;
        send_udp_multicast(socket, IPV6_MULTICAST_ADDR, port, &packet)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_client_creation_fails_without_config() {
        // This should fail if not running as root or if keys don't exist
        let result = AuthenticationClient::new("testuser".to_string());
        // We expect this to fail in test environment
        assert!(result.is_err());
    }
}
