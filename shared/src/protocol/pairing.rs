use prost::Message as ProstMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::{
    decrypt_with_psk, derive_psk_from_x25519, derive_sas, encrypt_with_psk, ClientSymmetricKey,
    Ed25519KeyPair, PairingSymmetricKey, X25519KeyPair,
};
use crate::protocol::pb::*;
use crate::protocol::ProtocolError;

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
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
    pub fn new(ed25519_keypair: Ed25519KeyPair) -> Self {
        Self {
            x25519_keypair: X25519KeyPair::generate(),
            ed25519_keypair,
            server_x25519_public: None,
            psk: None,
            sas: None,
        }
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
        // Step 1: Client receives PairingHello from server
        let hello = self.receive_pairing_hello(&mut stream).await?;
        let server_device_name = hello.device_name;

        // Step 2: Derive PSK from X25519 key exchange
        self.server_x25519_public = Some(
            hello
                .x25519_public_key
                .as_slice()
                .try_into()
                .map_err(|_| ProtocolError::InvalidMessageFormat)?,
        );

        let _client_x25519_priv = self.x25519_keypair.secret_key_bytes();
        let client_x25519_pub = self.x25519_keypair.public_key_bytes();
        let server_x25519_pub = self.server_x25519_public.unwrap();

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

        let shared_secret = self
            .x25519_keypair
            .diffie_hellman(&self.server_x25519_public.unwrap())?;

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

        // Step 3: Derive and store SAS
        let client_x25519_pub = self.x25519_keypair.public_key_bytes();
        let server_x25519_pub = self.server_x25519_public.unwrap();
        let sas = derive_sas(
            self.psk.as_ref().unwrap(),
            &client_x25519_pub,
            &server_x25519_pub,
        )?;
        self.sas = Some(sas.clone());

        // Step 4: Send PairingResponse with our X25519 public key
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
        // Step 6: Send CSK encrypted with PSK to server along with username
        self.send_csk_message(&mut stream, csk, username).await?;

        // Step 7: Receive PairingComplete acknowledgment from server
        self.receive_pairing_complete(&mut stream).await?;

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
        let response = PairingResponse {
            version: PAIRING_VERSION,
            x25519_public_key: self.x25519_keypair.public_key_bytes().to_vec(),
            ed25519_public_key: self.ed25519_keypair.verifying_key_bytes().to_vec(),
            device_name: client_device_name.to_string(),
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
        let psk = self.psk.as_ref().unwrap();
        tracing::debug!(
            "PSK for encryption (sha256): {}",
            crate::protocol::messages::sha256_hex(psk.as_bytes())
        );
        tracing::debug!(
            "CSK to encrypt (sha256): {}",
            crate::protocol::messages::sha256_hex(csk.as_bytes())
        );

        let encrypted_csk = encrypt_with_psk(psk, b"csk_exchange", csk.as_bytes())?;

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

    async fn receive_pairing_complete(&self, stream: &mut TcpStream) -> Result<(), ProtocolError> {
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

        Ok(())
    }

    /// Get the current SAS for display
    pub fn sas(&self) -> Option<&str> {
        self.sas.as_deref()
    }
}

impl ServerPairingSession {
    /// Create a new server pairing session
    pub fn new(ed25519_public_key: [u8; 32]) -> Self {
        Self {
            x25519_keypair: X25519KeyPair::generate(),
            ed25519_public_key,
            client_x25519_public: None,
            psk: None,
            sas: None,
        }
    }

    /// Complete the pairing handshake as server
    /// Returns (CSK received from client, client_ed25519_public_key, client_device_name, SAS)
    pub async fn complete_pairing(
        &mut self,
        mut stream: TcpStream,
        server_device_name: &str,
    ) -> Result<(ClientSymmetricKey, [u8; 32], String, String), ProtocolError> {
        // Step 1: Send PairingHello with our X25519 public key
        self.send_pairing_hello(&mut stream, server_device_name)
            .await?;

        // Step 2: Receive client's PairingResponse
        let response = self.receive_pairing_response(&mut stream).await?;

        // Extract client device name
        let client_device_name = response.device_name.clone();

        // Step 3: Derive PSK from X25519 key exchange
        self.client_x25519_public = Some(
            response
                .x25519_public_key
                .as_slice()
                .try_into()
                .map_err(|_| ProtocolError::InvalidMessageFormat)?,
        );

        let shared_secret = self
            .x25519_keypair
            .diffie_hellman(&self.client_x25519_public.unwrap())?;
        let psk = derive_psk_from_x25519(&shared_secret)?;
        self.psk = Some(psk);

        // Step 4: Derive and store SAS (note: client is first, server is second)
        let client_x25519_pub = self.client_x25519_public.unwrap();
        let server_x25519_pub = self.x25519_keypair.public_key_bytes();
        let sas = derive_sas(
            self.psk.as_ref().unwrap(),
            &client_x25519_pub,
            &server_x25519_pub,
        )?;
        self.sas = Some(sas.clone());

        // Step 5: Wait for user SAS confirmation (done outside this function)

        // Step 6: Receive CSK encrypted with PSK from client
        let csk = self.receive_csk_message(&mut stream).await?;

        // Step 7: Send PairingComplete acknowledgment
        self.send_pairing_complete(&mut stream).await?;

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
    ) -> Result<ClientSymmetricKey, ProtocolError> {
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
        let psk = self.psk.as_ref().unwrap();
        tracing::debug!(
            "PSK for decryption (sha256): {}",
            sha256_hex(psk.as_bytes())
        );

        let plaintext = decrypt_with_psk(psk, b"csk_exchange", &encrypted_msg.encrypted_csk)?;

        tracing::debug!("Decrypted CSK (sha256): {}", sha256_hex(&plaintext));

        if plaintext.len() != 32 {
            return Err(ProtocolError::InvalidMessageFormat);
        }

        let mut csk_bytes = [0u8; 32];
        csk_bytes.copy_from_slice(&plaintext);

        Ok(ClientSymmetricKey::from_bytes(csk_bytes))
    }

    async fn send_pairing_complete(&self, stream: &mut TcpStream) -> Result<(), ProtocolError> {
        let complete = PairingComplete { success: true };

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
            let server_keypair = Ed25519KeyPair::generate();
            let mut session = ServerPairingSession::new(server_keypair.verifying_key_bytes());

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
            let client_keypair = Ed25519KeyPair::generate();
            let csk = ClientSymmetricKey::generate();
            let mut session = ClientPairingSession::new(client_keypair);

            let (_server_pub, _server_name, sas) = session
                .complete_pairing(stream, &csk, "testuser", "TestClient")
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
}
