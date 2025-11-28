use std::process::Command;

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

pub struct FirewallGuard {
    port: u16,
    protocol: Protocol,
}

impl FirewallGuard {
    pub fn new(port: u16, protocol: Protocol) -> Result<Self, String> {
        open_port(port, protocol)?;
        Ok(Self { port, protocol })
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        if let Err(e) = close_port(self.port, self.protocol) {
            tracing::error!("Failed to close firewall port: {}", e);
        }
    }
}

pub fn open_port(port: u16, protocol: Protocol) -> Result<(), String> {
    // Try to use firewalld first if available, as it's the modern standard
    // and mixing direct iptables rules with firewalld can cause issues.
    if is_firewalld_running() {
        add_firewalld_rule(port, protocol)?;
        tracing::info!(
            "Firewall (firewalld): Opened ephemeral port {}/{}",
            port,
            protocol
        );
        return Ok(());
    }

    // Fallback to iptables
    let status = Command::new("iptables")
        .args([
            "-I",
            "INPUT",
            "1",
            "-p",
            &protocol.to_string(),
            "--dport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])
        .status()
        .map_err(|e| format!("Failed to execute iptables: {}", e))?;

    if status.success() {
        tracing::info!(
            "Firewall (iptables): Opened ephemeral port {}/{}",
            port,
            protocol
        );
        Ok(())
    } else {
        Err(format!("Firewall command failed with status: {}", status))
    }
}

pub fn close_port(port: u16, protocol: Protocol) -> Result<(), String> {
    if is_firewalld_running() {
        if let Err(e) = remove_firewalld_rule(port, protocol) {
            return Err(format!(
                "Failed to close firewall port {}/{}: {}",
                port, protocol, e
            ));
        } else {
            tracing::info!(
                "Firewall (firewalld): Closed ephemeral port {}/{}",
                port,
                protocol
            );
        }
        return Ok(());
    }

    let _ = Command::new("iptables")
        .args([
            "-D",
            "INPUT",
            "-p",
            &protocol.to_string(),
            "--dport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])
        .status()
        .map_err(|e| {
            let msg = format!("Failed to close firewall port {}/{}: {}", port, protocol, e);
            tracing::error!("{}", msg);
            e
        });

    tracing::info!(
        "Firewall (iptables): Closed ephemeral port {}/{}",
        port,
        protocol
    );
    Ok(())
}

fn is_firewalld_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "firewalld"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn add_firewalld_rule(port: u16, protocol: Protocol) -> Result<(), String> {
    let status = Command::new("firewall-cmd")
        .args(["--add-port", &format!("{}/{}", port, protocol)])
        .status()
        .map_err(|e| format!("Failed to execute firewall-cmd: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("firewall-cmd failed with status: {}", status))
    }
}

fn remove_firewalld_rule(port: u16, protocol: Protocol) -> Result<(), String> {
    let status = Command::new("firewall-cmd")
        .args(["--remove-port", &format!("{}/{}", port, protocol)])
        .status()
        .map_err(|e| format!("Failed to execute firewall-cmd: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("firewall-cmd failed with status: {}", status))
    }
}
