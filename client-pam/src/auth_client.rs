use prost::Message;
use shared::{
    config::ClientConfigManager,
    crypto::{
        generate_current_temporal_identifier_ble, ClientSymmetricKey, CryptoError, Ed25519KeyPair,
    },
    network::{
        create_broadcast_socket, get_client_retry_interval, get_session_timeout, is_ipv6_available,
        send_udp_broadcast, send_udp_multicast_all_interfaces, try_receive_udp_packet,
        IPV6_MULTICAST_ADDR,
    },
    protocol::{
        messages::*,
        packet::*,
        pb::{wrapper_message, EncryptedPacket},
        ProtocolError,
    },
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "ble")]
use crate::ble_client::BleClient;

// Track whether we've warned about IPv6 unavailability
static IPV6_WARNING_SHOWN: AtomicBool = AtomicBool::new(false);

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
            tracing::warn!(
                "Total paired servers: {}, but none allow this user",
                paired_servers.len()
            );
            return Err(AuthError::NoPairedDevices);
        }

        tracing::info!(
            "{} server(s) authorized for user {} (out of {} total)",
            allowed_servers.len(),
            self.username,
            paired_servers.len()
        );

        // Create the authentication request using the challenge we generated
        let request = create_auth_request_with_challenge(
            &self.keypair,
            &self.username,
            &self.hostname,
            &self.challenge,
        )?;
        let wrapper = wrap_auth_request(request);

        // Create encrypted packet
        // Note: For authentication, we use a static nonce derived from CSK only,
        // since the challenge is INSIDE the encrypted message and can't be used
        // to derive the decryption nonce (chicken-egg problem).
        let packet = create_encrypted_packet_with_csk_nonce(&self.csk, &wrapper)?;

        // Start parallel discovery: UDP + BLE
        // According to spec, we race both transports and use whichever responds first
        #[cfg(feature = "ble")]
        {
            // Try both UDP and BLE in parallel
            self.try_parallel_authentication(&packet).await
        }

        #[cfg(not(feature = "ble"))]
        {
            // BLE not compiled, fall back to UDP only
            tracing::info!("BLE not available, using UDP only");
            self.try_udp_authentication(&packet).await
        }
    }

    #[cfg(feature = "ble")]
    /// Try authentication over both UDP and BLE in parallel (spec-compliant)
    async fn try_parallel_authentication(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        use tokio::select;

        tracing::debug!("==> try_parallel_authentication called");

        let temporal_id = generate_current_temporal_identifier_ble(&self.csk)?;
        tracing::info!("Starting parallel discovery over UDP and BLE");
        tracing::debug!("==> About to spawn UDP and BLE tasks");

        // Clone data for the BLE task
        let self_ble = self.clone();
        let packet_ble = packet.clone();
        let temporal_id_ble = temporal_id.clone();

        let mut ble_handle = tokio::spawn(async move {
            self_ble
                .try_ble_authentication(&packet_ble, &temporal_id_ble)
                .await
        });

        // Clone data for the UDP task
        let self_udp = self.clone();
        let packet_udp = packet.clone();

        let mut udp_handle =
            tokio::spawn(async move { self_udp.try_udp_authentication(&packet_udp).await });

        let mut ble_completed = false;
        let mut udp_completed = false;
        let mut udp_result: Option<Result<(), AuthError>> = None;

        tracing::debug!("==> Tasks spawned, entering select loop");

        loop {
            select! {
                // Poll the BLE JoinHandle
                result = &mut ble_handle, if !ble_completed => {
                    tracing::info!("BLE task completed"); // Log from the task handle
                    ble_completed = true;

                    match result {
                        // Task succeeded with Ok(())
                        Ok(Ok(())) => {
                            tracing::info!("BLE authentication granted");
                            udp_handle.abort(); // Cancel UDP task
                            return Ok(());
                        }
                        // Task succeeded with Err(Denied)
                        Ok(Err(AuthError::Denied)) => {
                            tracing::warn!("BLE authentication explicitly denied");
                            udp_handle.abort(); // Cancel UDP task
                            return Err(AuthError::Denied);
                        }
                        // Task succeeded with a different error
                        Ok(Err(ref e)) => {
                            // THIS IS THE CRITICAL LOGIC:
                            // We log and continue, waiting for UDP. We do NOT return.
                            tracing::warn!("BLE failed: {}, waiting for UDP", e);
                        }
                        // Task panicked or was cancelled
                        Err(join_err) => {
                            tracing::error!("BLE task failed to execute: {}", join_err);
                        }
                    }
                }
                // Poll the UDP JoinHandle
                result = &mut udp_handle, if !udp_completed => {
                    tracing::info!("UDP task completed");
                    udp_completed = true;

                    match result {
                        // Task succeeded with Ok(())
                        Ok(Ok(())) => {
                            tracing::info!("UDP authentication granted");
                            ble_handle.abort(); // Cancel BLE task
                            return Ok(());
                        }
                        // Task succeeded with an error
                        Ok(Err(e)) => {
                            tracing::warn!("UDP authentication failed: {}", e);
                            udp_result = Some(Err(e)); // Store the UDP error
                        }
                        // Task panicked or was cancelled
                        Err(join_err) => {
                            tracing::error!("UDP task failed to execute: {}", join_err);
                            udp_result = Some(Err(AuthError::InitError(format!("UDP task failed: {}", join_err))));
                        }
                    }
                }
            }

            // Check if *both* have completed
            if ble_completed && udp_completed {
                tracing::warn!("Both BLE and UDP authentication failed");
                // Both failed. We return the stored UDP result.
                // If UDP was OK but BLE failed, udp_result is None,
                // but our logic above would have returned Ok(()) from the UDP branch.
                // Therefore, if we reach this point, udp_result *must* contain an error.
                return udp_result.unwrap();
            }
        }
    }

    #[cfg(feature = "ble")]
    /// Try authentication over BLE via the daemon
    async fn try_ble_authentication(
        &self,
        packet: &EncryptedPacket,
        temporal_id: &[u8; 10],
    ) -> Result<(), AuthError> {
        tracing::info!("Starting BLE authentication via daemon");

        // Create BLE client
        let client = BleClient::new()
            .await
            .map_err(|e| AuthError::BleError(format!("Failed to create BLE client: {}", e)))?;

        // Check if daemon is available
        if !client.is_daemon_available().await {
            return Err(AuthError::BleError(
                "BLE daemon is not available".to_string(),
            ));
        }

        // Encode the packet
        let mut packet_bytes = Vec::new();
        packet
            .encode(&mut packet_bytes)
            .map_err(|e| AuthError::BleError(format!("Failed to encode packet: {}", e)))?;

        // Call the daemon
        let timeout_secs = get_session_timeout().as_secs();
        let result = client
            .authenticate(packet_bytes, temporal_id.to_vec(), timeout_secs)
            .await
            .map_err(|e| AuthError::BleError(format!("D-Bus call failed: {}", e)))?;

        // Convert result to authentication outcome
        match result {
            shared::AuthResult::Granted => {
                tracing::info!("BLE authentication granted by daemon");
                Ok(())
            }
            shared::AuthResult::Denied => {
                tracing::warn!("BLE authentication denied by daemon");
                Err(AuthError::Denied)
            }
            shared::AuthResult::Timeout => {
                tracing::warn!("BLE authentication timed out");
                Err(AuthError::Timeout)
            }
            shared::AuthResult::Error => {
                tracing::error!("BLE authentication error from daemon");
                Err(AuthError::BleError("Daemon returned error".to_string()))
            }
        }
    }

    /// Try authentication over UDP (IPv4 broadcast + IPv6 multicast)
    #[allow(unused_assignments)]
    async fn try_udp_authentication(&self, packet: &EncryptedPacket) -> Result<(), AuthError> {
        let socket = create_broadcast_socket().await?;
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
            if let Err(e) = send_udp_broadcast(&socket, port, packet).await {
                tracing::warn!("Failed to send IPv4 broadcast: {}", e);
            }

            // Send multicast on IPv6 (on all available interfaces)
            if is_ipv6_available() {
                match send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, port, packet).await {
                    Ok(count) if count > 0 => {
                        tracing::trace!("Sent IPv6 multicast on {} interface(s)", count);
                    }
                    Ok(_) => {
                        if !IPV6_WARNING_SHOWN.swap(true, Ordering::Relaxed) {
                            tracing::info!("No suitable IPv6 interfaces found for multicast");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to send IPv6 multicast: {}", e);
                    }
                }
            } else if !IPV6_WARNING_SHOWN.swap(true, Ordering::Relaxed) {
                // Only warn once about IPv6 being unavailable
                tracing::info!("IPv6 not available, using IPv4 broadcast only");
            }

            // Wait for response
            let retry_interval = get_client_retry_interval(attempt);
            match try_receive_udp_packet(&socket, retry_interval).await? {
                Some((response_packet, server_addr)) => {
                    // Try to decrypt and process response
                    match self.process_response(&response_packet, server_addr).await {
                        Ok(true) => {
                            // Authentication granted
                            tracing::info!("Processing successful grant response");
                            if !confirmation_sent {
                                tracing::debug!("Sending confirmation to server");
                                self.send_confirmation(&socket, port).await?;
                                confirmation_sent = true;
                                tracing::debug!("Confirmation sent successfully");
                            }

                            // Send cancel to other servers
                            tracing::debug!("Sending cancel broadcast to other servers");
                            self.send_cancel_broadcast(&socket, port).await?;
                            tracing::info!("UDP authentication completed successfully, returning");

                            return Ok(());
                        }
                        Ok(false) => {
                            // Authentication denied
                            // Per spec: must send GrantConfirmation to halt retransmissions
                            tracing::info!("Processing denial response");
                            if !confirmation_sent {
                                tracing::debug!(
                                    "Sending confirmation to server to halt retransmissions"
                                );
                                self.send_confirmation(&socket, port).await?;
                                confirmation_sent = true;
                            }
                            return Err(AuthError::Denied);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to process response from {}: {}",
                                server_addr,
                                e
                            );
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
        server_addr: SocketAddr,
    ) -> Result<bool, AuthError> {
        // Decrypt the packet using CSK-derived nonce (same as authentication request)
        let wrapper = decrypt_encrypted_packet_with_csk_nonce(&self.csk, packet)?;

        tracing::info!(
            "Received message from {}: {:?}",
            server_addr,
            match &wrapper.payload {
                Some(wrapper_message::Payload::AuthGrant(_)) => "AuthGrant",
                Some(wrapper_message::Payload::AuthDenial(_)) => "AuthDenial",
                Some(wrapper_message::Payload::AuthRequest(_)) => "AuthRequest",
                _ => "Unknown",
            }
        );

        // Check what kind of response we got
        match wrapper.payload {
            Some(wrapper_message::Payload::AuthGrant(grant)) => {
                // Verify the grant
                // We need to find which server sent this by checking signatures
                let paired_servers = self.config_manager.load_paired_servers()?;

                tracing::info!(
                    "Trying to verify grant against {} paired servers",
                    paired_servers.len()
                );
                tracing::info!(
                    "Grant signature length: {}, signed_challenge length: {}",
                    grant.signature.len(),
                    grant.signed_challenge.len()
                );
                // Sensitive values: log only truncated fingerprint and length
                tracing::debug!(
                    "Challenge (trunc): {}… (len={})",
                    hex::encode(&self.challenge[..std::cmp::min(8, self.challenge.len())]),
                    self.challenge.len()
                );

                for (_id, server) in paired_servers.iter() {
                    let pub_key_bytes = hex::decode(&server.public_key)
                        .map_err(|_| AuthError::Protocol(ProtocolError::InvalidMessageFormat))?;

                    if pub_key_bytes.len() != 32 {
                        tracing::warn!(
                            "Server {} has invalid public key length: {}",
                            server.name,
                            pub_key_bytes.len()
                        );
                        continue;
                    }

                    let mut pub_key = [0u8; 32];
                    pub_key.copy_from_slice(&pub_key_bytes);

                    tracing::info!(
                        "Trying server: {} with public key: {}",
                        server.name,
                        server.public_key
                    );
                    tracing::debug!(
                        "Grant signature (trunc): {}… (len={})",
                        hex::encode(&grant.signature[..std::cmp::min(8, grant.signature.len())]),
                        grant.signature.len()
                    );
                    tracing::debug!(
                        "Signed challenge (trunc): {}… (len={})",
                        hex::encode(
                            &grant.signed_challenge
                                [..std::cmp::min(8, grant.signed_challenge.len())]
                        ),
                        grant.signed_challenge.len()
                    );

                    match verify_auth_grant(&grant, &self.challenge, &pub_key) {
                        Ok(_) => {
                            tracing::info!("Authentication granted by server: {}", server.name);
                            return Ok(true);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Verification failed for server {}: {:?}",
                                server.name,
                                e
                            );
                        }
                    }
                }

                tracing::error!("No server matched the grant signature");
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
        socket: &tokio::net::UdpSocket,
        port: u16,
    ) -> Result<(), AuthError> {
        let confirmation = create_grant_confirmation(&self.keypair, &self.challenge)?;
        let wrapper = wrap_grant_confirmation(confirmation);
        let packet = create_encrypted_packet_with_csk_nonce(&self.csk, &wrapper)?;

        // Send on both IPv4 and IPv6 (if available)
        send_udp_broadcast(socket, port, &packet).await?;
        if is_ipv6_available() {
            let _ = send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, port, &packet).await;
        }

        Ok(())
    }

    /// Send cancel broadcast to all servers
    async fn send_cancel_broadcast(
        &self,
        socket: &tokio::net::UdpSocket,
        port: u16,
    ) -> Result<(), AuthError> {
        let cancel = create_auth_cancel(&self.keypair, &self.challenge)?;
        let wrapper = wrap_auth_cancel(cancel);
        let packet = create_encrypted_packet_with_csk_nonce(&self.csk, &wrapper)?;

        // Send on both IPv4 and IPv6 (if available)
        send_udp_broadcast(socket, port, &packet).await?;
        if is_ipv6_available() {
            let _ = send_udp_multicast_all_interfaces(IPV6_MULTICAST_ADDR, port, &packet).await;
        }

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
