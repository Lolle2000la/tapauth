use prost::Message as ProstMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::{
    decrypt_with_psk, derive_psk_from_x25519, derive_sas, encrypt_with_psk, ClientSymmetricKey,
    Ed25519KeyPair, PairingSymmetricKey, X25519KeyPair,
};
use crate::protocol::pb::*;
use crate::protocol::ProtocolError;

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

    /// Complete the pairing handshake as client
    /// Returns (CSK, server_ed25519_public_key, SAS)
    pub async fn complete_pairing(
        &mut self,
        mut stream: TcpStream,
    ) -> Result<(ClientSymmetricKey, [u8; 32], String), ProtocolError> {
        // Step 1: Receive server's PairingHello
        let hello = self.receive_pairing_hello(&mut stream).await?;

        // Step 2: Derive PSK from X25519 key exchange
        self.server_x25519_public = Some(
            hello
                .x25519_public_key
                .as_slice()
                .try_into()
                .map_err(|_| ProtocolError::InvalidMessageFormat)?,
        );

        let shared_secret = self
            .x25519_keypair
            .diffie_hellman(&self.server_x25519_public.unwrap())?;
        let psk = derive_psk_from_x25519(&shared_secret)?;
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
        self.send_pairing_response(&mut stream).await?;

        // Step 5: Wait for user SAS confirmation (done outside this function)
        // This is where the GUI would show the SAS and wait for user confirmation

        // Step 6: Receive CSK encrypted with PSK
        let csk_message = self.receive_csk_message(&mut stream).await?;

        // Step 7: Send PairingComplete acknowledgment
        self.send_pairing_complete(&mut stream).await?;

        let server_ed25519_public: [u8; 32] = hello
            .ed25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidMessageFormat)?;

        Ok((csk_message, server_ed25519_public, sas))
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

    async fn send_pairing_response(&self, stream: &mut TcpStream) -> Result<(), ProtocolError> {
        let response = PairingResponse {
            version: PAIRING_VERSION,
            x25519_public_key: self.x25519_keypair.public_key_bytes().to_vec(),
            ed25519_public_key: self.ed25519_keypair.verifying_key_bytes().to_vec(),
        };

        let buf = response.encode_to_vec();
        stream.write_u32(buf.len() as u32).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;

        Ok(())
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

        // Decrypt CSK with PSK
        let plaintext = decrypt_with_psk(
            self.psk.as_ref().unwrap(),
            b"csk_exchange",
            &encrypted_msg.encrypted_csk,
        )?;

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
    /// Returns (client_ed25519_public_key, SAS)
    pub async fn complete_pairing(
        &mut self,
        mut stream: TcpStream,
        csk: &ClientSymmetricKey,
    ) -> Result<([u8; 32], String), ProtocolError> {
        // Step 1: Send PairingHello with our X25519 public key
        self.send_pairing_hello(&mut stream).await?;

        // Step 2: Receive client's PairingResponse
        let response = self.receive_pairing_response(&mut stream).await?;

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

        // Step 6: Send CSK encrypted with PSK
        self.send_csk_message(&mut stream, csk).await?;

        // Step 7: Receive PairingComplete acknowledgment
        self.receive_pairing_complete(&mut stream).await?;

        let client_ed25519_public: [u8; 32] = response
            .ed25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidMessageFormat)?;

        Ok((client_ed25519_public, sas))
    }

    async fn send_pairing_hello(&self, stream: &mut TcpStream) -> Result<(), ProtocolError> {
        let hello = PairingHello {
            version: PAIRING_VERSION,
            x25519_public_key: self.x25519_keypair.public_key_bytes().to_vec(),
            ed25519_public_key: self.ed25519_public_key.to_vec(),
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

    async fn send_csk_message(
        &self,
        stream: &mut TcpStream,
        csk: &ClientSymmetricKey,
    ) -> Result<(), ProtocolError> {
        // Encrypt CSK with PSK
        let encrypted_csk =
            encrypt_with_psk(self.psk.as_ref().unwrap(), b"csk_exchange", csk.as_bytes())?;

        let message = PairingCskMessage { encrypted_csk };

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_pairing_handshake() {
        // Start a TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server task
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let server_keypair = Ed25519KeyPair::generate();
            let csk = ClientSymmetricKey::generate();
            let mut session = ServerPairingSession::new(server_keypair.verifying_key_bytes());

            session.complete_pairing(stream, &csk).await.unwrap();
            (csk, session.sas().unwrap().to_string())
        });

        // Client task
        let client_task = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            let stream = TcpStream::connect(addr).await.unwrap();
            let client_keypair = Ed25519KeyPair::generate();
            let mut session = ClientPairingSession::new(client_keypair);

            let (csk, _server_pub, sas) = session.complete_pairing(stream).await.unwrap();
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
