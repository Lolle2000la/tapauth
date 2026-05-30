use std::collections::HashMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

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

/// Reference-counted active ports: maps port → number of active guards.
/// A firewall rule is only opened when the count goes from 0→1 and only
/// closed when it drops back to 0, preventing concurrent auth sessions
/// from prematurely tearing down the rule while another session is active.
static ACTIVE_PORTS: OnceLock<Mutex<HashMap<u16, usize>>> = OnceLock::new();

fn active_ports() -> &'static Mutex<HashMap<u16, usize>> {
    ACTIVE_PORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub struct FirewallGuard {
    port: u16,
    protocol: Protocol,
}

impl FirewallGuard {
    pub fn new(port: u16, protocol: Protocol) -> Result<Self, String> {
        let mut ports = active_ports()
            .lock()
            .map_err(|e| format!("active-ports lock poisoned: {}", e))?;
        let count = ports.entry(port).or_insert(0);
        if *count == 0 {
            open_port(port, protocol)?;
        }
        *count = count.checked_add(1).unwrap_or(usize::MAX);
        Ok(Self { port, protocol })
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        let port = self.port;
        let protocol = self.protocol;

        let do_close = {
            let mut ports = match active_ports().lock() {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!("active-ports lock poisoned on drop: {}", e);
                    return;
                }
            };
            match ports.get_mut(&port) {
                Some(count) => {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        ports.remove(&port);
                        true
                    } else {
                        false
                    }
                }
                None => {
                    tracing::warn!(
                        "FirewallGuard dropped for port {} but no entry in active_ports",
                        port
                    );
                    false
                }
            }
        };

        if do_close {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn_blocking(move || {
                    if let Err(e) = close_port(port, protocol) {
                        tracing::error!("Failed to close firewall port: {}", e);
                    }
                });
            } else {
                std::thread::spawn(move || {
                    if let Err(e) = close_port(port, protocol) {
                        tracing::error!("Failed to close firewall port: {}", e);
                    }
                });
            }
        }
    }
}

pub fn open_port(port: u16, protocol: Protocol) -> Result<(), String> {
    if is_firewalld_running() {
        add_firewalld_rule(port, protocol)?;
        tracing::info!(
            "Firewall (firewalld): Opened ephemeral port {}/{}",
            port,
            protocol
        );
        return Ok(());
    }

    let result = Command::new("iptables")
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
        .status();

    match result {
        Ok(status) if status.success() => {
            tracing::info!(
                "Firewall (iptables): Opened ephemeral port {}/{}",
                port,
                protocol
            );
            Ok(())
        }
        Ok(status) => Err(format!("iptables command failed with status: {}", status)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                "Neither firewalld nor iptables found on host; skipping automated port allocation"
            );
            Ok(())
        }
        Err(e) => Err(format!("Failed to execute iptables: {}", e)),
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

    let result = Command::new("iptables")
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
        .status();

    match result {
        Ok(status) if !status.success() => {
            Err(format!("iptables -D failed with exit status: {}", status))
        }
        Ok(_) => {
            tracing::info!(
                "Firewall (iptables): Closed ephemeral port {}/{}",
                port,
                protocol
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("iptables binary not found; skipping automated port cleanup");
            Ok(())
        }
        Err(e) => Err(format!("Failed to execute iptables -D: {}", e)),
    }
}

/// Cached firewalld status to avoid spawning `systemctl` on every open/close.
static FIREWALLD_RUNNING: OnceLock<bool> = OnceLock::new();

fn is_firewalld_running() -> bool {
    *FIREWALLD_RUNNING.get_or_init(|| {
        Command::new("systemctl")
            .args(["is-active", "--quiet", "firewalld"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
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
