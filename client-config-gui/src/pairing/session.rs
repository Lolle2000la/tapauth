use shared::{crypto::Ed25519KeyPair, protocol::ClientPairingSession};
use std::process::Command;
use tokio::net::{TcpListener, TcpStream};

pub struct FirewallGuard {
    port: u16,
}

impl FirewallGuard {
    pub fn new(port: u16) -> Result<Self, String> {
        let status = Command::new("iptables")
            .args([
                "-I",
                "INPUT",
                "1",
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "ACCEPT",
            ])
            .status()
            .map_err(|e| format!("Failed to execute iptables: {}", e))?;

        if status.success() {
            tracing::info!("Firewall: Opened ephemeral port {}", port);
            Ok(Self { port })
        } else {
            Err(format!("Firewall command failed with status: {}", status))
        }
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        let _ = Command::new("iptables")
            .args([
                "-D",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                &self.port.to_string(),
                "-j",
                "ACCEPT",
            ])
            .status()
            .map_err(|e| {
                tracing::error!("Failed to close firewall port {}: {}", self.port, e);
                e
            });

        tracing::info!("Firewall: Closed ephemeral port {}", self.port);
    }
}

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
