use shared::{firewall::FirewallGuard, protocol::ClientPairingSession};
use tokio::net::{TcpListener, TcpStream};

pub struct PendingPairingState {
    pub listener: TcpListener,
    pub firewall_guard: FirewallGuard,
}

pub struct PairingSessionState {
    pub stream: TcpStream,
    pub session: ClientPairingSession,
    pub server_public_key: [u8; 32],
    pub server_device_name: String,
    #[allow(dead_code)]
    pub firewall_guard: FirewallGuard,
}

pub enum SessionState {
    None,
    Pending(PendingPairingState),
    Active(Box<PairingSessionState>),
}
