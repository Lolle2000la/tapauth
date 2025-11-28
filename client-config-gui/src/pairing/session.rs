use shared::{crypto::Ed25519KeyPair, firewall::FirewallGuard, protocol::ClientPairingSession};
use tokio::net::{TcpListener, TcpStream};

pub struct PendingPairingState {
    pub listener: TcpListener,
    pub firewall_guard: FirewallGuard,
    #[allow(dead_code)]
    pub pairing_url: String,
}

pub struct PairingSessionState {
    pub stream: TcpStream,
    pub session: ClientPairingSession,
    pub server_public_key: [u8; 32],
    pub server_device_name: String,
    #[allow(dead_code)]
    pub keypair: Ed25519KeyPair,
    #[allow(dead_code)]
    pub _firewall_guard: FirewallGuard,
}

pub enum SessionState {
    None,
    Pending(PendingPairingState),
    Active(Box<PairingSessionState>),
}
