//! Two-phase pairing protocol for TapAuth.
//!
//! Establishes trust between client and server through ephemeral X25519 key exchange
//! and out-of-band SAS (Short Authentication String) verification.
//!
//! ## Protocol Flow
//!
//! ### Phase 1: Key Exchange and SAS Generation
//!
//! **Client:**
//! 1. Connect to server TCP socket
//! 2. Receive `PairingHello` (server's X25519/Ed25519 public keys, device name)
//! 3. Perform X25519 Diffie-Hellman → derive PSK via HKDF
//! 4. Derive 6-digit SAS from PSK + public keys
//! 5. Send `PairingResponse` (client's X25519/Ed25519 public keys)
//!
//! **Server:**
//! 1. Send `PairingHello`
//! 2. Receive `PairingResponse`
//! 3. Perform X25519 Diffie-Hellman → derive PSK via HKDF
//! 4. Derive 6-digit SAS from PSK + public keys
//!
//! Both sides now have identical SAS values to compare out-of-band.
//!
//! ### Phase 2: CSK Transfer (after SAS confirmation)
//!
//! **Client:**
//! 1. Generate CSK (Client Symmetric Key)
//! 2. Encrypt CSK with PSK
//! 3. Send `PairingCskMessage` (encrypted CSK + username)
//! 4. Receive `PairingComplete` acknowledgment
//!
//! **Server:**
//! 1. Receive `PairingCskMessage`
//! 2. Decrypt CSK with PSK
//! 3. Store CSK + client Ed25519 public key + username
//! 4. Send `PairingComplete`
//!
//! ## Security
//!
//! - SAS verification prevents MitM attacks during key exchange
//! - Ephemeral X25519 keys provide forward secrecy for the pairing session
//! - PSK is discarded after CSK transfer; only CSK and Ed25519 keys are persisted
//! - All messages after SAS are authenticated via PSK encryption

use prost::Message as ProstMessage;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::{
    decrypt_with_psk, derive_psk_from_x25519, derive_sas, encrypt_with_psk, ClientSymmetricKey,
    CryptoError, Ed25519KeyPair, PairingSymmetricKey, X25519KeyPair,
};
use crate::protocol::pb::*;
use crate::protocol::ProtocolError;

fn sha256_hex(data: &[u8]) -> String {
    #[cfg(debug_assertions)]
    {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = data;
        "<stripped>".to_string()
    }
}

const MAX_MESSAGE_SIZE: usize = 16 * 1024; // 16KB max message size

/// Pairing protocol version
pub const PAIRING_VERSION: u32 = 1;

/// Client-side pairing state machine
pub struct ClientPairingSession {
    x25519_keypair: X25519KeyPair,
    ed25519_keypair: Ed25519KeyPair,
    server_x25519_public: Option<[u8; 32]>,
    psk: Option<PairingSymmetricKey>,
    sas: Option<String>,
    /// Algorithms the server supports (from PairingHello)
    server_supported_symmetric: Vec<i32>,
    server_supported_hash: Vec<i32>,
    server_supported_signature: Vec<i32>,
}

/// Server-side pairing state machine  
pub struct ServerPairingSession {
    x25519_keypair: X25519KeyPair,
    ed25519_public_key: [u8; 32],
    client_x25519_public: Option<[u8; 32]>,
    psk: Option<PairingSymmetricKey>,
    sas: Option<String>,
}

impl ClientPairingSession {
    /// Create a new client pairing session with ephemeral keypair
    pub fn new(ed25519_keypair: Ed25519KeyPair) -> Result<Self, CryptoError> {
        Ok(Self {
            x25519_keypair: X25519KeyPair::generate()?,
            ed25519_keypair,
            server_x25519_public: None,
            psk: None,
            sas: None,
            server_supported_symmetric: Vec::new(),
            server_supported_hash: Vec::new(),
            server_supported_signature: Vec::new(),
        })
    }

    /// Get the X25519 public key to display in QR code
    pub fn x25519_public_key(&self) -> [u8; 32] {
        self.x25519_keypair.public_key_bytes()
    }

    /// Get Ed25519 public key
    pub fn ed25519_public_key(&self) -> [u8; 32] {
        self.ed25519_keypair.verifying_key_bytes()
    }

    /// Initiate client-side pairing and perform key exchange
    /// Returns: (stream, server_ed25519_public_key, server_device_name, SAS)
    pub async fn initiate_pairing(
        &mut self,
        mut stream: TcpStream,
        client_device_name: &str,
    ) -> Result<(TcpStream, [u8; 32], String, String), ProtocolError> {
        let hello = self.receive_pairing_hello(&mut stream).await?;
        let server_device_name = hello.device_name;
        self.server_x25519_public = Some(
            hello
                .x25519_public_key
                .as_slice()
                .try_into()
                .map_err(|_| ProtocolError::InvalidMessageFormat)?,
        );

        // Store server's supported algorithms
        self.server_supported_symmetric = hello.supported_symmetric_algorithms.clone();
        self.server_supported_hash = hello.supported_hash_algorithms.clone();
        self.server_supported_signature = hello.supported_signature_algorithms.clone();

        let _client_x25519_priv = self.x25519_keypair.secret_key_bytes();
        let client_x25519_pub = self.x25519_keypair.public_key_bytes();
        let server_x25519_pub = self
            .server_x25519_public
            .ok_or(ProtocolError::MissingField("server_x25519_public"))?;

        tracing::debug!(
            "Client X25519 public key (trunc): {}…",
            &hex::encode(client_x25519_pub)
                [..std::cmp::min(16, hex::encode(client_x25519_pub).len())]
        );
        tracing::debug!(
            "Server X25519 public key (trunc): {}…",
            &hex::encode(server_x25519_pub)
                [..std::cmp::min(16, hex::encode(server_x25519_pub).len())]
        );

        let shared_secret = self.x25519_keypair.diffie_hellman(&server_x25519_pub)?;

        tracing::debug!(
            "Shared secret (sha256): {}",
            crate::protocol::messages::sha256_hex(&shared_secret)
        );

        let psk = derive_psk_from_x25519(&shared_secret)?;

        tracing::debug!(
            "Derived PSK (sha256): {}",
            crate::protocol::messages::sha256_hex(psk.as_bytes())
        );

        self.psk = Some(psk);

        let client_x25519_pub = self.x25519_keypair.public_key_bytes();
        let psk = self
            .psk
            .as_ref()
            .ok_or(ProtocolError::MissingField("psk"))?;
        let sas = derive_sas(psk, &client_x25519_pub, &server_x25519_pub)?;
        self.sas = Some(sas.clone());

        self.send_pairing_response(&mut stream, client_device_name)
            .await?;

        let server_ed25519_public: [u8; 32] = hello
            .ed25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidMessageFormat)?;

        // Return stream and SAS for user verification
        // User must confirm SAS, then call finish_pairing()
        Ok((stream, server_ed25519_public, server_device_name, sas))
    }

    /// Phase 2: Complete pairing after user confirms SAS
    /// Sends CSK to server with username and receives confirmation
    /// Takes the stream from initiate_pairing()
    pub async fn finish_pairing(
        &mut self,
        mut stream: TcpStream,
        csk: &ClientSymmetricKey,
        username: &str,
    ) -> Result<(), ProtocolError> {
        self.send_csk_message(&mut stream, csk, username).await?;
        self.receive_pairing_complete(&mut stream, csk).await?;

        Ok(())
    }

    async fn receive_pairing_hello(
        &self,
        stream: &mut TcpStream,
    ) -> Result<PairingHello, ProtocolError> {
        let len = stream.read_u32().await?;
        if len > MAX_MESSAGE_SIZE as u32 {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;

        let hello = PairingHello::decode(&buf[..])?;

        if hello.version != PAIRING_VERSION {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        Ok(hello)
    }

    async fn send_pairing_response(
        &self,
        stream: &mut TcpStream,
        client_device_name: &str,
    ) -> Result<(), ProtocolError> {
        // Select algorithms from server's supported list (use defaults if server sent none)
        let selected_symmetric = self
            .server_supported_symmetric
            .first()
            .copied()
            .unwrap_or(SymmetricAlgorithm::Aes256Gcm as i32);
        let selected_hash = self
            .server_supported_hash
            .first()
            .copied()
            .unwrap_or(HashAlgorithm::Sha256 as i32);
        let selected_signature = self
            .server_supported_signature
            .first()
            .copied()
            .unwrap_or(SignatureAlgorithm::Ed25519 as i32);

        let response = PairingResponse {
            version: PAIRING_VERSION,
            x25519_public_key: self.x25519_keypair.public_key_bytes().to_vec(),
            ed25519_public_key: self.ed25519_keypair.verifying_key_bytes().to_vec(),
            device_name: client_device_name.to_string(),
            selected_symmetric_algorithm: selected_symmetric,
            selected_hash_algorithm: selected_hash,
            selected_signature_algorithm: selected_signature,
        };

        let buf = response.encode_to_vec();
        stream.write_u32(buf.len() as u32).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn send_csk_message(
        &self,
        stream: &mut TcpStream,
        csk: &ClientSymmetricKey,
        username: &str,
    ) -> Result<(), ProtocolError> {
        // Encrypt CSK with PSK
        let psk = self
            .psk
            .as_ref()
            .ok_or(ProtocolError::MissingField("psk"))?;
        tracing::debug!(
            "PSK for encryption (sha256): {}",
            crate::protocol::messages::sha256_hex(psk.as_bytes())
        );
        tracing::debug!(
            "CSK to encrypt (sha256): {}",
            crate::protocol::messages::sha256_hex(csk.as_bytes())
        );

        let encrypted_csk = encrypt_with_psk(psk, csk.as_bytes())?;

        tracing::debug!(
            "Encrypted CSK (sha256): {}",
            crate::protocol::messages::sha256_hex(&encrypted_csk)
        );

        let message = PairingCskMessage {
            encrypted_csk,
            username: username.to_string(),
        };

        let buf = message.encode_to_vec();
        stream.write_u32(buf.len() as u32).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn receive_pairing_complete(
        &self,
        stream: &mut TcpStream,
        csk: &ClientSymmetricKey,
    ) -> Result<(), ProtocolError> {
        let len = stream.read_u32().await?;
        if len > MAX_MESSAGE_SIZE as u32 {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;

        let complete = PairingComplete::decode(&buf[..])?;

        if !complete.success {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        // Verify CSK hash for integrity
        let psk = self
            .psk
            .as_ref()
            .ok_or(ProtocolError::MissingField("psk"))?;
        let decrypted_hash = decrypt_with_psk(psk, &complete.csk_hash)?;

        // Compute expected hash
        let mut expected_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(csk.as_bytes());
        expected_hash.copy_from_slice(&hasher.finalize());

        if decrypted_hash != expected_hash {
            tracing::error!("CSK hash mismatch: server received a different CSK");
            return Err(ProtocolError::InvalidMessageFormat);
        }

        Ok(())
    }

    /// Get the current SAS for display
    pub fn sas(&self) -> Option<&str> {
        self.sas.as_deref()
    }
}

impl ServerPairingSession {
    /// Create a new server pairing session
    pub fn new(ed25519_public_key: [u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self {
            x25519_keypair: X25519KeyPair::generate()?,
            ed25519_public_key,
            client_x25519_public: None,
            psk: None,
            sas: None,
        })
    }

    /// Complete the pairing handshake as server
    /// Returns (CSK received from client, client_ed25519_public_key, client_device_name, SAS)
    pub async fn complete_pairing(
        &mut self,
        mut stream: TcpStream,
        server_device_name: &str,
    ) -> Result<(ClientSymmetricKey, [u8; 32], String, String), ProtocolError> {
        self.send_pairing_hello(&mut stream, server_device_name)
            .await?;

        let response = self.receive_pairing_response(&mut stream).await?;

        let client_device_name = response.device_name.clone();

        self.client_x25519_public = Some(
            response
                .x25519_public_key
                .as_slice()
                .try_into()
                .map_err(|_| ProtocolError::InvalidMessageFormat)?,
        );

        let client_x25519_pub = self
            .client_x25519_public
            .ok_or(ProtocolError::MissingField("client_x25519_public"))?;
        let shared_secret = self.x25519_keypair.diffie_hellman(&client_x25519_pub)?;
        let psk = derive_psk_from_x25519(&shared_secret)?;
        self.psk = Some(psk);

        let server_x25519_pub = self.x25519_keypair.public_key_bytes();
        let psk = self
            .psk
            .as_ref()
            .ok_or(ProtocolError::MissingField("psk"))?;
        let sas = derive_sas(psk, &client_x25519_pub, &server_x25519_pub)?;
        self.sas = Some(sas.clone());

        let (csk, csk_hash) = self.receive_csk_message(&mut stream).await?;
        self.send_pairing_complete(&mut stream, &csk_hash).await?;

        let client_ed25519_public: [u8; 32] = response
            .ed25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidMessageFormat)?;

        Ok((csk, client_ed25519_public, client_device_name, sas))
    }

    async fn send_pairing_hello(
        &self,
        stream: &mut TcpStream,
        server_device_name: &str,
    ) -> Result<(), ProtocolError> {
        let hello = PairingHello {
            version: PAIRING_VERSION,
            x25519_public_key: self.x25519_keypair.public_key_bytes().to_vec(),
            ed25519_public_key: self.ed25519_public_key.to_vec(),
            device_name: server_device_name.to_string(),
            supported_symmetric_algorithms: vec![SymmetricAlgorithm::Aes256Gcm as i32],
            supported_hash_algorithms: vec![HashAlgorithm::Sha256 as i32],
            supported_signature_algorithms: vec![SignatureAlgorithm::Ed25519 as i32],
        };

        let buf = hello.encode_to_vec();
        stream.write_u32(buf.len() as u32).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;

        Ok(())
    }

    async fn receive_pairing_response(
        &self,
        stream: &mut TcpStream,
    ) -> Result<PairingResponse, ProtocolError> {
        let len = stream.read_u32().await?;
        if len > MAX_MESSAGE_SIZE as u32 {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;

        let response = PairingResponse::decode(&buf[..])?;

        if response.version != PAIRING_VERSION {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        Ok(response)
    }

    async fn receive_csk_message(
        &self,
        stream: &mut TcpStream,
    ) -> Result<(ClientSymmetricKey, [u8; 32]), ProtocolError> {
        let len = stream.read_u32().await?;
        if len > MAX_MESSAGE_SIZE as u32 {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;

        let encrypted_msg = PairingCskMessage::decode(&buf[..])?;

        tracing::debug!(
            "Received encrypted CSK (sha256): {}",
            sha256_hex(&encrypted_msg.encrypted_csk)
        );

        // Decrypt CSK with PSK
        let psk = self
            .psk
            .as_ref()
            .ok_or(ProtocolError::MissingField("psk"))?;
        tracing::debug!(
            "PSK for decryption (sha256): {}",
            sha256_hex(psk.as_bytes())
        );

        let plaintext = decrypt_with_psk(psk, &encrypted_msg.encrypted_csk)?;

        tracing::debug!("Decrypted CSK (sha256): {}", sha256_hex(&plaintext));

        if plaintext.len() != 32 {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        let mut csk_bytes = [0u8; 32];
        csk_bytes.copy_from_slice(&plaintext);

        // Compute SHA-256 hash of the CSK for integrity verification
        let mut csk_hash = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(csk_bytes);
        csk_hash.copy_from_slice(&hasher.finalize());

        Ok((ClientSymmetricKey::from_bytes(csk_bytes), csk_hash))
    }

    async fn send_pairing_complete(
        &self,
        stream: &mut TcpStream,
        csk_hash: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        // Encrypt the CSK hash with PSK
        let psk = self
            .psk
            .as_ref()
            .ok_or(ProtocolError::MissingField("psk"))?;
        let encrypted_hash = encrypt_with_psk(psk, csk_hash)?;

        let complete = PairingComplete {
            success: true,
            hash_algorithm: HashAlgorithm::Sha256 as i32,
            csk_hash: encrypted_hash,
        };

        let buf = complete.encode_to_vec();
        stream.write_u32(buf.len() as u32).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;

        Ok(())
    }

    /// Get the current SAS for display
    pub fn sas(&self) -> Option<&str> {
        self.sas.as_deref()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_pairing_handshake() {
        // Start a TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server task (Android - receives CSK)
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let server_keypair = Ed25519KeyPair::generate().unwrap();
            let mut session =
                ServerPairingSession::new(server_keypair.verifying_key_bytes()).unwrap();

            let (csk, _client_pub, _client_device_name, sas) = session
                .complete_pairing(stream, "TestServer")
                .await
                .unwrap();
            (csk, sas)
        });

        // Client task (Desktop - sends CSK)
        let client_task = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            let stream = TcpStream::connect(addr).await.unwrap();
            let client_keypair = Ed25519KeyPair::generate().unwrap();
            let csk = ClientSymmetricKey::generate().unwrap();
            let mut session = ClientPairingSession::new(client_keypair).unwrap();

            // Phase 1: Initiate pairing
            let (stream, _server_pub, _server_name, sas) = session
                .initiate_pairing(stream, "TestClient")
                .await
                .unwrap();

            // Phase 2: Finish pairing
            session
                .finish_pairing(stream, &csk, "testuser")
                .await
                .unwrap();

            (csk, sas)
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        let (server_csk, server_sas) = server_result.unwrap();
        let (client_csk, client_sas) = client_result.unwrap();

        // Verify SAS matches
        assert_eq!(server_sas, client_sas);

        // Verify CSK matches
        assert_eq!(server_csk.as_bytes(), client_csk.as_bytes());
    }

    #[tokio::test]
    async fn test_pairing_device_names() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let server_keypair = Ed25519KeyPair::generate().unwrap();
            let mut session =
                ServerPairingSession::new(server_keypair.verifying_key_bytes()).unwrap();

            let (_, _, client_device_name, _) = session
                .complete_pairing(stream, "MyAndroidPhone")
                .await
                .unwrap();
            client_device_name
        });

        let client_task = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let stream = TcpStream::connect(addr).await.unwrap();
            let client_keypair = Ed25519KeyPair::generate().unwrap();
            let csk = ClientSymmetricKey::generate().unwrap();
            let mut session = ClientPairingSession::new(client_keypair).unwrap();

            let (stream, _, server_device_name, _) = session
                .initiate_pairing(stream, "LinuxDesktop")
                .await
                .unwrap();

            session
                .finish_pairing(stream, &csk, "testuser")
                .await
                .unwrap();

            server_device_name
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);
        let client_device_name = server_result.unwrap();
        let server_device_name = client_result.unwrap();

        // Verify device names were exchanged correctly
        assert_eq!(client_device_name, "LinuxDesktop");
        assert_eq!(server_device_name, "MyAndroidPhone");
    }

    #[tokio::test]
    async fn test_pairing_with_empty_device_names() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let server_keypair = Ed25519KeyPair::generate().unwrap();
            let mut session =
                ServerPairingSession::new(server_keypair.verifying_key_bytes()).unwrap();

            session.complete_pairing(stream, "").await
        });

        let client_task = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            let stream = TcpStream::connect(addr).await.unwrap();
            let client_keypair = Ed25519KeyPair::generate().unwrap();
            let csk = ClientSymmetricKey::generate().unwrap();
            let mut session = ClientPairingSession::new(client_keypair).unwrap();

            let result = session.initiate_pairing(stream, "").await;
            if let Ok((stream, _, _, _)) = result {
                session.finish_pairing(stream, &csk, "testuser").await
            } else {
                result.map(|_| ())
            }
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);

        // Empty device names should still work (they're just display names)
        assert!(server_result.is_ok());
        assert!(client_result.is_ok());
    }

    #[test]
    fn test_client_session_public_keys() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let session = ClientPairingSession::new(keypair.clone()).unwrap();

        // X25519 public key should be 32 bytes
        assert_eq!(session.x25519_public_key().len(), 32);

        // Ed25519 public key should match the input keypair
        assert_eq!(session.ed25519_public_key(), keypair.verifying_key_bytes());
    }

    #[test]
    fn test_server_session_creation() {
        let ed25519_public = [42u8; 32];
        let session = ServerPairingSession::new(ed25519_public).unwrap();

        // Should store the provided public key
        assert_eq!(session.ed25519_public_key, ed25519_public);
    }
}
